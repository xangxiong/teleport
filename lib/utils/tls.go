/*
Copyright 2015 Gravitational, Inc.

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

package utils

import (
	"crypto/tls"
)

// TLSConfig returns default TLS configuration strong defaults.
func TLSConfig(cipherSuites []uint16) *tls.Config {
	config := &tls.Config{}
	SetupTLSConfig(config, cipherSuites)
	return config
}

// SetupTLSConfig sets up cipher suites in existing TLS config
func SetupTLSConfig(config *tls.Config, cipherSuites []uint16) {
	// If ciphers suites were passed in, use them. Otherwise use the the
	// Go defaults.
	if len(cipherSuites) > 0 {
		config.CipherSuites = cipherSuites
	}

	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = false
	config.ClientSessionCache = tls.NewLRUClientSessionCache(DefaultLRUCapacity)
}

const (
	// DefaultLRUCapacity is a capacity for LRU session cache
	DefaultLRUCapacity = 1024
	// // DefaultCertTTL sets the TTL of the self-signed certificate (1 year)
	// DefaultCertTTL = (24 * time.Hour) * 365
)

// DefaultCipherSuites returns the default list of cipher suites that
// Teleport supports. By default Teleport only support modern ciphers
// (Chacha20 and AES GCM) and key exchanges which support perfect forward
// secrecy (ECDHE).
//
// Note that TLS_RSA_WITH_AES_128_GCM_SHA{256,384} have been dropped due to
// being banned by HTTP2 which breaks GRPC clients. For more information see:
// https://tools.ietf.org/html/rfc7540#appendix-A. These two can still be
// manually added if needed.
func DefaultCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,

		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
}
