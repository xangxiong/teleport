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
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/fxamacker/cbor/v2"
	"github.com/gravitational/trace"

	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
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
	CCR *wanlib.CredentialCreationResponse

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

// Register creates a new Secure Enclave-backed biometric credential.
// Callers are encouraged to either explicitly Confirm or Rollback the returned
// registration.
// See Registration.
func Register(origin string, cc *wanlib.CredentialCreation) (*Registration, error) {
	if !IsAvailable() {
		return nil, ErrNotAvailable
	}

	// Ignored cc fields:
	// - Timeout - we don't control touch ID timeouts (also the server is free to
	//   enforce it)
	// - CredentialExcludeList - we always allow re-registering (for various
	//   reasons).
	// - Extensions - none supported
	// - Attestation - we always to our best (packed/self-attestation).
	//   The server is free to ignore/reject.
	switch {
	case origin == "":
		return nil, errors.New("origin required")
	case cc == nil:
		return nil, errors.New("credential creation required")
	case len(cc.Response.Challenge) == 0:
		return nil, errors.New("challenge required")
	// Note: we don't need other RelyingParty fields, but technically they would
	// be required as well.
	case cc.Response.RelyingParty.ID == "":
		return nil, errors.New("relying party ID required")
	case len(cc.Response.User.ID) == 0:
		return nil, errors.New("user ID required")
	case cc.Response.User.Name == "":
		return nil, errors.New("user name required")
	case cc.Response.AuthenticatorSelection.AuthenticatorAttachment == protocol.CrossPlatform:
		return nil, fmt.Errorf("cannot fulfill authenticator attachment %q", cc.Response.AuthenticatorSelection.AuthenticatorAttachment)
	}
	ok := false
	for _, param := range cc.Response.Parameters {
		// ES256 is all we can do.
		if param.Type == protocol.PublicKeyCredentialType && param.Algorithm == webauthncose.AlgES256 {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("cannot fulfill credential parameters, only ES256 are supported")
	}

	rpID := cc.Response.RelyingParty.ID
	user := cc.Response.User.Name
	userHandle := cc.Response.User.ID

	// TODO(codingllama): Handle double registrations and failures after key
	//  creation.
	resp, err := native.Register(rpID, user, userHandle)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	credentialID := resp.CredentialID
	pubKeyRaw := resp.publicKeyRaw

	// Parse public key and transform to the required CBOR object.
	pubKey, err := pubKeyFromRawAppleKey(pubKeyRaw)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	x := make([]byte, 32) // x and y must have exactly 32 bytes in EC2PublicKeyData.
	y := make([]byte, 32)
	pubKey.X.FillBytes(x)
	pubKey.Y.FillBytes(y)

	pubKeyCBOR, err := cbor.Marshal(
		&webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{
				KeyType:   int64(webauthncose.EllipticKey),
				Algorithm: int64(webauthncose.AlgES256),
			},
			// See https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.
			Curve:  1, // P-256
			XCoord: x,
			YCoord: y,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attData, err := makeAttestationData(
		protocol.CreateCeremony, origin, rpID, cc.Response.Challenge,
		&credentialData{
			id:         credentialID,
			pubKeyCBOR: pubKeyCBOR,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	promptPlatform()
	sig, err := native.Authenticate(nil /* actx */, credentialID, attData.digest)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attObj, err := cbor.Marshal(protocol.AttestationObject{
		RawAuthData: attData.rawAuthData,
		Format:      "packed",
		AttStatement: map[string]interface{}{
			"alg": int64(webauthncose.AlgES256),
			"sig": sig,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ccr := &wanlib.CredentialCreationResponse{
		PublicKeyCredential: wanlib.PublicKeyCredential{
			Credential: wanlib.Credential{
				ID:   credentialID,
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: []byte(credentialID),
		},
		AttestationResponse: wanlib.AuthenticatorAttestationResponse{
			AuthenticatorResponse: wanlib.AuthenticatorResponse{
				ClientDataJSON: attData.ccdJSON,
			},
			AttestationObject: attObj,
		},
	}
	return &Registration{
		CCR:          ccr,
		credentialID: credentialID,
	}, nil
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

// Login authenticates using a Secure Enclave-backed biometric credential.
// It returns the assertion response and the user that owns the credential to
// sign it.
func Login(origin, user string, assertion *wanlib.CredentialAssertion, picker CredentialPicker) (*wanlib.CredentialAssertionResponse, string, error) {
	if !IsAvailable() {
		return nil, "", ErrNotAvailable
	}

	// Ignored assertion fields:
	// - Timeout - we don't control touch ID timeouts (also the server is free to
	//   enforce it)
	// - UserVerification - always performed
	// - Extensions - none supported
	switch {
	case origin == "":
		return nil, "", errors.New("origin required")
	case assertion == nil:
		return nil, "", errors.New("assertion required")
	case len(assertion.Response.Challenge) == 0:
		return nil, "", errors.New("challenge required")
	case assertion.Response.RelyingPartyID == "":
		return nil, "", errors.New("relying party ID required")
	case picker == nil:
		return nil, "", errors.New("picker required")
	}

	rpID := assertion.Response.RelyingPartyID
	infos, err := native.FindCredentials(rpID, user)
	switch {
	case err != nil:
		return nil, "", trace.Wrap(err)
	case len(infos) == 0:
		return nil, "", ErrCredentialNotFound
	}

	// If everything else is equal, prefer newer credentials.
	sort.Slice(infos, func(i, j int) bool {
		i1 := infos[i]
		i2 := infos[j]
		// Sorted in descending order.
		return i1.CreateTime.After(i2.CreateTime)
	})

	// Prepare authentication context and prompt for the credential picker.
	actx := native.NewAuthContext()
	defer actx.Close()

	var prompted bool
	promptOnce := func() {
		if prompted {
			return
		}
		promptPlatform()
		prompted = true
	}

	cred, err := pickCredential(
		actx,
		infos, assertion.Response.AllowedCredentials,
		picker, promptOnce, user != "" /* userRequested */)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	log.Debugf("Touch ID: using credential %q", cred.CredentialID)

	attData, err := makeAttestationData(protocol.AssertCeremony, origin, rpID, assertion.Response.Challenge, nil /* cred */)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	promptOnce() // In case the picker prompt didn't happen.
	sig, err := native.Authenticate(actx, cred.CredentialID, attData.digest)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	return &wanlib.CredentialAssertionResponse{
		PublicKeyCredential: wanlib.PublicKeyCredential{
			Credential: wanlib.Credential{
				ID:   cred.CredentialID,
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: []byte(cred.CredentialID),
		},
		AssertionResponse: wanlib.AuthenticatorAssertionResponse{
			AuthenticatorResponse: wanlib.AuthenticatorResponse{
				ClientDataJSON: attData.ccdJSON,
			},
			AuthenticatorData: attData.rawAuthData,
			Signature:         sig,
			UserHandle:        cred.User.UserHandle,
		},
	}, cred.User.Name, nil
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