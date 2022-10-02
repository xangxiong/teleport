// Copyright 2021 Gravitational, Inc
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

package webauthncli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"

	"github.com/gravitational/trace"
)

type u2fRegistrationResponse struct {
	PubKey                                *ecdsa.PublicKey
	KeyHandle, AttestationCert, Signature []byte
}

func parseU2FRegistrationResponse(resp []byte) (*u2fRegistrationResponse, error) {
	// Reference:
	// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-response-message-success

	// minRespLen is based on:
	// 1 byte reserved +
	// 65 pubKey +
	// 1 key handle length +
	// N key handle (at least 1) +
	// N attestation cert (at least 1, need to parse to find out) +
	// N signature (at least 1, spec says 71-73 bytes, YMMV)
	const pubKeyLen = 65
	const minRespLen = 1 + pubKeyLen + 4
	if len(resp) < minRespLen {
		return nil, trace.BadParameter("U2F response too small, got %v bytes, expected at least %v", len(resp), minRespLen)
	}

	// Reads until the key handle length are guaranteed by the size checking
	// above.
	buf := resp
	if buf[0] != 0x05 {
		return nil, trace.BadParameter("invalid reserved byte: %v", buf[0])
	}
	buf = buf[1:]

	// public key
	x, y := elliptic.Unmarshal(elliptic.P256(), buf[:pubKeyLen])
	if x == nil {
		return nil, trace.BadParameter("failed to parse public key")
	}
	buf = buf[pubKeyLen:]
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// key handle
	l := int(buf[0])
	buf = buf[1:]
	// Size checking resumed from now on.
	if len(buf) < l {
		return nil, trace.BadParameter("key handle length is %v, but only %v bytes are left", l, len(buf))
	}
	keyHandle := buf[:l]
	buf = buf[l:]

	// Parse the certificate to figure out its size, then call
	// x509.ParseCertificate with a correctly-sized byte slice.
	sig, err := asn1.Unmarshal(buf, &asn1.RawValue{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Parse the cert to check that it is valid - we don't actually need the
	// parsed cert after it is proved to be well-formed.
	attestationCert := buf[:len(buf)-len(sig)]
	if _, err := x509.ParseCertificate(attestationCert); err != nil {
		return nil, trace.Wrap(err)
	}

	return &u2fRegistrationResponse{
		PubKey:          pubKey,
		KeyHandle:       keyHandle,
		AttestationCert: attestationCert,
		Signature:       sig,
	}, nil
}
