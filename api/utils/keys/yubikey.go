//go:build !linux || libpcsclite
// +build !linux libpcsclite

/*
Copyright 2022 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	fmt "fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api"
	attestation "github.com/gravitational/teleport/api/gen/proto/go/attestation/v1"
	"github.com/gravitational/teleport/api/utils/retryutils"
)

const (
	// PIVCardTypeYubiKey is the PIV card type assigned to yubiKeys.
	PIVCardTypeYubiKey = "yubikey"
)

var (
	// We use slot 9a for Teleport Clients which require `private_key_policy: hardware_key`.
	pivSlotNoTouch = piv.SlotAuthentication
	// We use slot 9c for Teleport Clients which require `private_key_policy: hardware_key_touch`.
	// Private keys generated on this slot will use TouchPolicy=Cached.
	pivSlotWithTouch = piv.SlotSignature
)

func getOrGenerateYubiKeyPrivateKey(ctx context.Context, serialNumber uint32, touchRequired bool) (*PrivateKey, error) {
	y, err := findYubiKeyBySerialNumber(ctx, serialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get the correct PIV slot and Touch policy for the given touch requirement.
	pivSlot := pivSlotNoTouch
	touchPolicy := piv.TouchPolicyNever
	if touchRequired {
		pivSlot = pivSlotWithTouch
		touchPolicy = piv.TouchPolicyCached
	}

	// First, check if there is already a private key set up by a Teleport Client.
	priv, err := y.getPrivateKey(ctx, pivSlot)
	if err != nil {
		// Generate a new private key on the PIV slot.
		if priv, err = y.generatePrivateKey(ctx, pivSlot, touchPolicy); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	keyPEM, err := priv.keyPEM()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewPrivateKey(priv, keyPEM)
}

// YubiKeyPrivateKey is a YubiKey PIV private key. Cryptographical operations open
// a new temporary connection to the PIV card to perform the operation.
type YubiKeyPrivateKey struct {
	// yubiKey is a specific yubiKey PIV module.
	*yubiKey
	pivSlot piv.Slot
	pub     crypto.PublicKey
	// ctx is used when opening a connection to the PIV module,
	// which occurs with a retry loop.
	ctx context.Context
}

// yubiKeyPrivateKeyData is marshalable data used to retrieve a specific yubiKey PIV private key.
type yubiKeyPrivateKeyData struct {
	SerialNumber uint32 `json:"serial_number"`
	SlotKey      uint32 `json:"slot_key"`
}

func newYubiKeyPrivateKey(ctx context.Context, y *yubiKey, slot piv.Slot, pub crypto.PublicKey) (*YubiKeyPrivateKey, error) {
	return &YubiKeyPrivateKey{
		yubiKey: y,
		pivSlot: slot,
		pub:     pub,
		ctx:     ctx,
	}, nil
}

func parseYubiKeyPrivateKeyData(keyDataBytes []byte) (*YubiKeyPrivateKey, error) {
	// TODO (Joerger): rather than requiring a context be passed here, we should
	// pre-load the yubikey PIV connection to avoid retry/context logic occurring
	// at spontaneous points in the code (anywhere a private key is used).
	ctx := context.TODO()

	var keyData yubiKeyPrivateKeyData
	if err := json.Unmarshal(keyDataBytes, &keyData); err != nil {
		return nil, trace.Wrap(err)
	}

	pivSlot, err := parsePIVSlot(keyData.SlotKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	y, err := findYubiKeyBySerialNumber(ctx, keyData.SerialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	priv, err := y.getPrivateKey(ctx, pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return priv, nil
}

// Public returns the public key corresponding to this private key.
func (y *YubiKeyPrivateKey) Public() crypto.PublicKey {
	return y.pub
}

// Sign implements crypto.Signer.
func (y *YubiKeyPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	yk, err := y.open(y.ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	privateKey, err := yk.PrivateKey(y.pivSlot, y.pub, piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if y.pivSlot == pivSlotWithTouch {
		cancelTouchPrompt := delayedTouchPrompt(y.ctx)
		defer cancelTouchPrompt()
	}

	return privateKey.(crypto.Signer).Sign(rand, digest, opts)
}

func (y *YubiKeyPrivateKey) keyPEM() ([]byte, error) {
	keyDataBytes, err := json.Marshal(yubiKeyPrivateKeyData{
		SerialNumber: y.serialNumber,
		SlotKey:      y.pivSlot.Key,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    pivYubiKeyPrivateKeyType,
		Headers: nil,
		Bytes:   keyDataBytes,
	}), nil
}

// GetAttestationRequest returns an AttestationRequest for this YubiKeyPrivateKey.
func (y *YubiKeyPrivateKey) GetAttestationRequest() (*AttestationRequest, error) {
	yk, err := y.open(y.ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	slotCert, err := yk.Attest(y.pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AttestationRequest{
		AttestationRequest: &attestation.AttestationRequest_YubikeyAttestationRequest{
			YubikeyAttestationRequest: &attestation.YubiKeyAttestationRequest{
				SlotCert:        slotCert.Raw,
				AttestationCert: attCert.Raw,
			},
		},
	}, nil
}

// GetPrivateKeyPolicy returns the PrivateKeyPolicy supported by this YubiKeyPrivateKey.
func (k *YubiKeyPrivateKey) GetPrivateKeyPolicy() PrivateKeyPolicy {
	switch k.pivSlot {
	case pivSlotNoTouch:
		return PrivateKeyPolicyHardwareKey
	case pivSlotWithTouch:
		return PrivateKeyPolicyHardwareKeyTouch
	default:
		return PrivateKeyPolicyNone
	}
}

// yubiKey is a specific yubiKey PIV card.
type yubiKey struct {
	// card is a reader name used to find and connect to this yubiKey.
	// This value may change between OS's, or with other system changes.
	card string
	// serialNumber is the yubiKey's 8 digit serial number.
	serialNumber uint32
}

func newYubiKey(ctx context.Context, card string) (*yubiKey, error) {
	y := &yubiKey{card: card}

	yk, err := y.open(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	y.serialNumber, err = yk.Serial()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return y, nil
}

// generatePrivateKey generates a new private key from the given PIV slot with the given PIV policies.
func (y *yubiKey) generatePrivateKey(ctx context.Context, slot piv.Slot, touchPolicy piv.TouchPolicy) (*YubiKeyPrivateKey, error) {
	yk, err := y.open(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	opts := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: touchPolicy,
	}

	if touchPolicy == piv.TouchPolicyCached {
		cancelTouchPrompt := delayedTouchPrompt(ctx)
		defer cancelTouchPrompt()
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, slot, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a self signed certificate and store it in the PIV slot so that other
	// Teleport Clients know to reuse the stored key instead of genearting a new one.
	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cert, err := selfSignedTeleportClientCertificate(priv, pub)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Store a self-signed certificate to mark this slot as used by tsh.
	if err = yk.SetCertificate(piv.DefaultManagementKey, slot, cert); err != nil {
		return nil, trace.Wrap(err)
	}

	return newYubiKeyPrivateKey(ctx, y, slot, pub)
}

// getPrivateKey gets an existing private key from the given PIV slot.
func (y *yubiKey) getPrivateKey(ctx context.Context, slot piv.Slot) (*YubiKeyPrivateKey, error) {
	yk, err := y.open(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	// Check the slot's certificate to see if it contains a self signed Teleport Client cert.
	cert, err := yk.Certificate(slot)
	if err != nil || cert == nil {
		return nil, trace.NotFound("YubiKey certificate slot is empty, expected a Teleport Client cert")
	} else if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != certOrgName {
		return nil, trace.NotFound("YubiKey certificate slot contained unknown certificate:\n%+v", cert)
	}

	// Attest the key to make sure it hasn't been imported.
	slotCert, err := yk.Attest(slot)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	attestationCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if _, err = piv.Verify(attestationCert, slotCert); err != nil {
		return nil, trace.Wrap(err)
	}

	// Verify that the slot's certs have the same public key, otherwise the key
	// may have been generated by a non-teleport client.
	if pubComparer, ok := cert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool }); !ok {
		return nil, trace.BadParameter("certificate's public key of type %T is not a supported public key", cert.PublicKey)
	} else if !pubComparer.Equal(slotCert.PublicKey) {
		return nil, trace.NotFound("YubiKey slot contains mismatched certificates and must be regenerated")
	}

	return newYubiKeyPrivateKey(ctx, y, slot, slotCert.PublicKey)
}

// open a connection to yubiKey PIV module. The returned connection should be closed once
// it's been used. The yubiKey PIV module itself takes some additional time to handle closed
// connections, so we use a retry loop to give the PIV module time to close prior connections.
func (y *yubiKey) open(ctx context.Context) (yk *piv.YubiKey, err error) {
	linearRetry, err := retryutils.NewLinear(retryutils.LinearConfig{
		First: time.Millisecond * 50,
		Step:  time.Millisecond * 50,
		Max:   time.Second,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	isRetryError := func(error) bool {
		retryError := "connecting to smart card: the smart card cannot be accessed because of other connections outstanding"
		return strings.Contains(err.Error(), retryError)
	}

	// Backoff and retry for up to 10 seconds
	retryCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	err = linearRetry.For(retryCtx, func() error {
		yk, err = piv.Open(y.card)
		if err != nil && !isRetryError(err) {
			return retryutils.PermanentRetryError(err)
		}
		return trace.Wrap(err)
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return yk, nil
}

// findYubiKey finds a yubiKey PIV card and returns it's serial number.
func findYubiKey(ctx context.Context) (uint32, error) {
	yubiKeyCards, err := findYubiKeyCards()
	if err != nil {
		return 0, trace.Wrap(err)
	}

	if len(yubiKeyCards) == 0 {
		return 0, trace.NotFound("no yubiKey devices found")
	}

	y, err := newYubiKey(ctx, yubiKeyCards[0])
	if err != nil {
		return 0, trace.Wrap(err)
	}
	return y.serialNumber, nil
}

// findYubiKeyBySerialNumber finds a yubiKey PIV card by serial number.
func findYubiKeyBySerialNumber(ctx context.Context, serialNumber uint32) (*yubiKey, error) {
	yubiKeyCards, err := findYubiKeyCards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(yubiKeyCards) == 0 {
		return nil, trace.NotFound("no yubiKey devices found")
	}

	for _, card := range yubiKeyCards {
		y, err := newYubiKey(ctx, card)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if y.serialNumber == serialNumber {
			return y, nil
		}
	}

	return nil, trace.NotFound("no yubiKey device found with serial number %q", serialNumber)
}

// findYubiKeyCards returns a list of connected yubiKey PIV card names.
func findYubiKeyCards() ([]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var yubiKeyCards []string
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), PIVCardTypeYubiKey) {
			yubiKeyCards = append(yubiKeyCards, card)
		}
	}

	return yubiKeyCards, nil
}

func parsePIVSlot(slotKey uint32) (piv.Slot, error) {
	switch slotKey {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, nil
	case piv.SlotSignature.Key:
		return piv.SlotSignature, nil
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, nil
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, nil
	default:
		retiredSlot, ok := piv.RetiredKeyManagementSlot(slotKey)
		if !ok {
			return piv.Slot{}, trace.BadParameter("slot %X does not exist", slotKey)
		}
		return retiredSlot, nil
	}
}

// certOrgName is used to identify Teleport Client self-signed certificates stored in yubiKey PIV slots.
const certOrgName = "teleport"

func selfSignedTeleportClientCertificate(priv crypto.PrivateKey, pub crypto.PublicKey) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit) // see crypto/tls/generate_cert.go
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		PublicKey:    pub,
		Subject: pkix.Name{
			Organization:       []string{certOrgName},
			OrganizationalUnit: []string{api.Version},
		},
	}
	if cert.Raw, err = x509.CreateCertificate(rand.Reader, cert, cert, pub, priv); err != nil {
		return nil, trace.Wrap(err)
	}
	return cert, nil
}

// attestYubikey verifies that the given slot certificate chains to the attestation certificate,
// which chains to a Yubico CA.
func attestYubikey(req *attestation.YubiKeyAttestationRequest) (*AttestationResponse, error) {
	slotCert, err := x509.ParseCertificate(req.SlotCert)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	attestationCert, err := x509.ParseCertificate(req.AttestationCert)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	attestation, err := piv.Verify(attestationCert, slotCert)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	policy := PrivateKeyPolicyHardwareKey
	if attestation.TouchPolicy == piv.TouchPolicyAlways || attestation.TouchPolicy == piv.TouchPolicyCached {
		policy = PrivateKeyPolicyHardwareKeyTouch
	}

	pubDER, err := x509.MarshalPKIXPublicKey(slotCert.PublicKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AttestationResponse{
		PublicKeyDER:     pubDER,
		PrivateKeyPolicy: policy,
	}, nil
}

// delayedTouchPrompt prompts for touch after a short delay, to prevent prompting for
// touch when touch is cached. Call the returned cancel func to cancel the prompt.
func delayedTouchPrompt(ctx context.Context) (cancel func()) {
	// Wait a split second before prompting the user for touch. If the user's touch
	// is cached, then the Sign will complete before we prompt the user.
	ctx, cancel = context.WithTimeout(ctx, time.Millisecond*100)
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Fprintln(os.Stderr, "Tap your YubiKey")
		}
	}()

	return cancel
}
