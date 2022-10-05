/*
Copyright 2017 Gravitational, Inc.

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

package tlsca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// GenerateSelfSignedCAWithSigner generates self-signed certificate authority used for internal inter-node communications
func GenerateSelfSignedCAWithSigner(signer crypto.Signer, entity pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, error) {
	return GenerateSelfSignedCAWithConfig(GenerateCAConfig{
		Signer:   signer,
		Entity:   entity,
		DNSNames: dnsNames,
		TTL:      ttl,
		Clock:    clockwork.NewRealClock(),
	})
}

// GenerateCAConfig defines the configuration for generating
// self-signed CA certificates
type GenerateCAConfig struct {
	Signer      crypto.Signer
	Entity      pkix.Name
	DNSNames    []string
	IPAddresses []net.IP
	TTL         time.Duration
	Clock       clockwork.Clock
}

// setDefaults imposes defaults on this configuration
func (r *GenerateCAConfig) setDefaults() {
	if r.Clock == nil {
		r.Clock = clockwork.NewRealClock()
	}
}

// GenerateSelfSignedCAWithConfig generates a new CA certificate from the specified
// configuration.
// Returns PEM-encoded private key/certificate payloads upon success
func GenerateSelfSignedCAWithConfig(config GenerateCAConfig) (certPEM []byte, err error) {
	config.setDefaults()
	notBefore := config.Clock.Now()
	notAfter := notBefore.Add(config.TTL)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// this is important, otherwise go will accept certificate authorities
	// signed by the same private key and having the same subject (happens in tests)
	config.Entity.SerialNumber = serialNumber.String()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       config.Entity,
		Subject:      config.Entity,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		// Note: KeyUsageCRLSign is set only to generate empty CRLs
		// Access authentication with Windows.
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, config.Signer.Public(), config.Signer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return certPEM, nil
}

// ParseCertificatePEM parses PEM-encoded certificate
func ParseCertificatePEM(bytes []byte) (*x509.Certificate, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing PEM encoded block")
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, trace.BadParameter("expected PEM-encoded block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	return cert, nil
}

// ParseCertificatePEM parses multiple PEM-encoded certificates
func ParseCertificatePEMs(bytes []byte) ([]*x509.Certificate, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing PEM encoded block")
	}
	var blocks []*pem.Block
	block, remaining := pem.Decode(bytes)
	for block != nil {
		blocks = append(blocks, block)
		block, remaining = pem.Decode(remaining)
	}
	var certs []*x509.Certificate
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// MarshalPublicKeyFromPrivateKeyPEM extracts public key from private key
// and returns PEM marshalled key
func MarshalPublicKeyFromPrivateKeyPEM(privateKey crypto.PrivateKey) ([]byte, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, trace.BadParameter("expected RSA key")
	}
	rsaPublicKey := rsaPrivateKey.Public()
	derBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: derBytes}), nil
}
