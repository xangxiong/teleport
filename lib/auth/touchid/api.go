// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package touchid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

var (
	ErrCredentialNotFound = errors.New("credential not found")
	ErrNotAvailable       = errors.New("touch ID not available")

	// PromptPlatformMessage is the message shown before Touch ID prompts.
	PromptPlatformMessage = "Using platform authenticator, follow the OS prompt"
	// PromptWriter is the writer used for prompt messages.
	PromptWriter io.Writer = os.Stderr
)

func promptPlatform() {
	if PromptPlatformMessage != "" {
		fmt.Fprintln(PromptWriter, PromptPlatformMessage)
	}
}

// AuthContext is an optional, shared authentication context.
// Allows reusing a single authentication prompt/gesture between different
// functions, provided the functions are invoked in a short time interval.
// Only used by native touchid implementations.
type AuthContext interface {
	// Guard guards the invocation of fn behind an authentication check.
	Guard(fn func()) error
	// Close closes the context, releasing any held resources.
	Close()
}

// nativeTID represents the native Touch ID interface.
// Implementors must provide a global variable called `native`.
type nativeTID interface {
	Diag() (*DiagResult, error)

	// NewAuthContext creates a new AuthContext.
	NewAuthContext() AuthContext

	// Register creates a new credential in the Secure Enclave.
	Register(rpID, user string, userHandle []byte) (*CredentialInfo, error)

	// Authenticate authenticates using the specified credential.
	// Requires user interaction.
	Authenticate(actx AuthContext, credentialID string, digest []byte) ([]byte, error)

	// FindCredentials finds credentials without user interaction.
	// An empty user means "all users".
	FindCredentials(rpID, user string) ([]CredentialInfo, error)

	// ListCredentials lists all registered credentials.
	// Requires user interaction.
	ListCredentials() ([]CredentialInfo, error)

	// DeleteCredential deletes a credential.
	// Requires user interaction.
	DeleteCredential(credentialID string) error

	// DeleteNonInteractive deletes a credential without user interaction.
	DeleteNonInteractive(credentialID string) error
}

// DiagResult is the result from a Touch ID self diagnostics check.
type DiagResult struct {
	HasCompileSupport       bool
	HasSignature            bool
	HasEntitlements         bool
	PassedLAPolicyTest      bool
	PassedSecureEnclaveTest bool
	// IsAvailable is true if Touch ID is considered functional.
	// It means enough of the preceding tests to enable the feature.
	IsAvailable bool
}

// CredentialInfo holds information about a Secure Enclave credential.
type CredentialInfo struct {
	CredentialID string
	RPID         string
	User         UserInfo
	PublicKey    *ecdsa.PublicKey
	CreateTime   time.Time

	// publicKeyRaw is used internally to return public key data from native
	// register requests.
	publicKeyRaw []byte
}

// UserInfo holds information about a credential owner.
type UserInfo struct {
	UserHandle []byte
	Name       string
}

var (
	cachedDiag   *DiagResult
	cachedDiagMU sync.Mutex
)

// IsAvailable returns true if Touch ID is available in the system.
// Typically, a series of checks is performed in an attempt to avoid false
// positives.
// See Diag.
func IsAvailable() bool {
	// IsAvailable guards most of the public APIs, so results are cached between
	// invocations to avoid user-visible delays.
	// Diagnostics are safe to cache. State such as code signature, entitlements
	// and system availability of Touch ID / Secure Enclave isn't something that
	// could change during program invocation.
	// The outlier here is having a closed macbook (aka clamshell mode), as that
	// does impede Touch ID APIs and is something that can change.
	cachedDiagMU.Lock()
	defer cachedDiagMU.Unlock()

	if cachedDiag == nil {
		var err error
		cachedDiag, err = Diag()
		if err != nil {
			log.WithError(err).Warn("Touch ID self-diagnostics failed")
			return false
		}
	}

	return cachedDiag.IsAvailable
}

// Diag returns diagnostics information about Touch ID support.
func Diag() (*DiagResult, error) {
	return native.Diag()
}

// Registration represents an ongoing registration, with an already-created
// Secure Enclave key.
// The created key may be used as-is, but callers are encouraged to explicitly
// Confirm or Rollback the registration.
// Rollback assumes the server-side registration failed and removes the created
// Secure Enclave key.
// Confirm may replace equivalent keys with the new key, at the implementation's
// discretion.
type Registration struct {
	credentialID string

	// done is atomically set to 1 after either Rollback or Confirm are called.
	done int32
}

// Confirm confirms the registration.
// Keys equivalent to the current registration may be replaced by it, at the
// implementation's discretion.
func (r *Registration) Confirm() error {
	// Set r.done to disallow rollbacks after Confirm is called.
	atomic.StoreInt32(&r.done, 1)
	return nil
}

// Rollback rolls back the registration, deleting the Secure Enclave key as a
// result.
func (r *Registration) Rollback() error {
	if !atomic.CompareAndSwapInt32(&r.done, 0, 1) {
		return nil
	}

	// Delete the newly-created credential.
	return native.DeleteNonInteractive(r.credentialID)
}

func pubKeyFromRawAppleKey(pubKeyRaw []byte) (*ecdsa.PublicKey, error) {
	// Verify key length to avoid a potential panic below.
	// 3 is the smallest number that clears it, but in practice 65 is the more
	// common length.
	// Apple's docs make no guarantees, hence no assumptions are made here.
	if len(pubKeyRaw) < 3 {
		return nil, fmt.Errorf("public key representation too small (%v bytes)", len(pubKeyRaw))
	}

	// "For an elliptic curve public key, the format follows the ANSI X9.63
	// standard using a byte string of 04 || X || Y. (...) All of these
	// representations use constant size integers, including leading zeros as
	// needed."
	// https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation?language=objc
	pubKeyRaw = pubKeyRaw[1:] // skip 0x04
	l := len(pubKeyRaw) / 2
	x := pubKeyRaw[:l]
	y := pubKeyRaw[l:]

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     (&big.Int{}).SetBytes(x),
		Y:     (&big.Int{}).SetBytes(y),
	}, nil
}

type credentialData struct {
	id         string
	pubKeyCBOR []byte
}

type attestationResponse struct {
	ccdJSON     []byte
	rawAuthData []byte
	digest      []byte
}

// TODO(codingllama): Share a single definition with webauthncli / mocku2f.
type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func makeAttestationData(ceremony protocol.CeremonyType, origin, rpID string, challenge []byte, cred *credentialData) (*attestationResponse, error) {
	// Sanity check.
	isCreate := ceremony == protocol.CreateCeremony
	if isCreate && cred == nil {
		return nil, fmt.Errorf("cred required for %q ceremony", ceremony)
	}

	ccd := &collectedClientData{
		Type:      string(ceremony),
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	}
	ccdJSON, err := json.Marshal(ccd)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ccdHash := sha256.Sum256(ccdJSON)
	rpIDHash := sha256.Sum256([]byte(rpID))

	flags := byte(protocol.FlagUserPresent | protocol.FlagUserVerified)
	if isCreate {
		flags |= byte(protocol.FlagAttestedCredentialData)
	}

	authData := &bytes.Buffer{}
	authData.Write(rpIDHash[:])
	authData.WriteByte(flags)
	binary.Write(authData, binary.BigEndian, uint32(0)) // signature counter
	// Attested credential data begins here.
	if isCreate {
		authData.Write(make([]byte, 16))                               // aaguid
		binary.Write(authData, binary.BigEndian, uint16(len(cred.id))) // credentialIdLength
		authData.Write([]byte(cred.id))
		authData.Write(cred.pubKeyCBOR)
	}
	rawAuthData := authData.Bytes()

	dataToSign := append(rawAuthData, ccdHash[:]...)
	digest := sha256.Sum256(dataToSign)
	return &attestationResponse{
		ccdJSON:     ccdJSON,
		rawAuthData: rawAuthData,
		digest:      digest[:],
	}, nil
}

// CredentialPicker allows users to choose a credential for login.
type CredentialPicker interface {
	// PromptCredential prompts the user to pick a credential from the list.
	// Prompts only happen if there is more than one credential to choose from.
	// Must return one of the pointers from the slice or an error.
	PromptCredential(creds []*CredentialInfo) (*CredentialInfo, error)
}

func pickCredential(
	actx AuthContext,
	infos []CredentialInfo, allowedCredentials []protocol.CredentialDescriptor,
	picker CredentialPicker, promptOnce func(), userRequested bool) (*CredentialInfo, error) {
	// Handle early exits.
	switch l := len(infos); {
	// MFA.
	case len(allowedCredentials) > 0:
		for _, info := range infos {
			for _, cred := range allowedCredentials {
				if info.CredentialID == string(cred.CredentialID) {
					return &info, nil
				}
			}
		}
		return nil, ErrCredentialNotFound

	// Single credential or specific user requested.
	// A requested user means that all credentials are for that user, so there
	// would be nothing to pick.
	case l == 1 || userRequested:
		return &infos[0], nil
	}

	// Dedup users to avoid confusion.
	// This assumes credentials are sorted from most to less preferred.
	knownUsers := make(map[string]struct{})
	deduped := make([]*CredentialInfo, 0, len(infos))
	for _, c := range infos {
		if _, ok := knownUsers[c.User.Name]; ok {
			continue
		}
		knownUsers[c.User.Name] = struct{}{}

		c := c // Avoid capture-by-reference errors
		deduped = append(deduped, &c)
	}
	if len(deduped) == 1 {
		return deduped[0], nil
	}

	promptOnce()
	var choice *CredentialInfo
	var choiceErr error
	if err := actx.Guard(func() {
		choice, choiceErr = picker.PromptCredential(deduped)
	}); err != nil {
		return nil, trace.Wrap(err)
	}
	if choiceErr != nil {
		return nil, trace.Wrap(choiceErr)
	}

	// Is choice a pointer within the slice?
	// We could work around this requirement, but it seems better to constrain the
	// picker API from the start.
	for _, c := range deduped {
		if c == choice {
			return choice, nil
		}
	}
	return nil, fmt.Errorf("picker returned invalid credential: %#v", choice)
}

// ListCredentials lists all registered Secure Enclave credentials.
// Requires user interaction.
func ListCredentials() ([]CredentialInfo, error) {
	if !IsAvailable() {
		return nil, ErrNotAvailable
	}

	promptPlatform()
	infos, err := native.ListCredentials()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Parse public keys.
	for i := range infos {
		info := &infos[i]
		key, err := pubKeyFromRawAppleKey(info.publicKeyRaw)
		if err != nil {
			log.Warnf("Failed to convert public key: %v", err)
		}
		info.PublicKey = key // this is OK, even if it's nil
		info.publicKeyRaw = nil
	}

	return infos, nil
}

// DeleteCredential deletes a Secure Enclave credential.
// Requires user interaction.
func DeleteCredential(credentialID string) error {
	if !IsAvailable() {
		return ErrNotAvailable
	}

	promptPlatform()
	return native.DeleteCredential(credentialID)
}
