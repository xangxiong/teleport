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

package auth

import (
	"context"
	"crypto/x509"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// RegisterParams specifies parameters
// for first time register operation with auth server
type RegisterParams struct {
	// Token is a secure token to join the cluster
	Token string
	// ID is identity ID
	ID IdentityID
	// Servers is a list of auth servers to dial
	Servers []utils.NetAddr
	// AdditionalPrincipals is a list of additional principals to dial
	AdditionalPrincipals []string
	// DNSNames is a list of DNS names to add to x509 certificate
	DNSNames []string
	// PublicTLSKey is a server's public key to sign
	PublicTLSKey []byte
	// PublicSSHKey is a server's public SSH key to sign
	PublicSSHKey []byte
	// CipherSuites is a list of cipher suites to use for TLS client connection
	CipherSuites []uint16
	// CAPins are the SKPI hashes of the CAs used to verify the Auth Server.
	CAPins []string
	// CAPath is the path to the CA file.
	CAPath string
	// GetHostCredentials is a client that can fetch host credentials.
	GetHostCredentials HostCredentials
	// Clock specifies the time provider. Will be used to override the time anchor
	// for TLS certificate verification.
	// Defaults to real clock if unspecified
	Clock clockwork.Clock
	// JoinMethod is the joining method used for this register request.
	JoinMethod types.JoinMethod
	// // ec2IdentityDocument is used for Simplified Node Joining to prove the
	// // identity of a joining EC2 instance.
	// ec2IdentityDocument []byte
	// CircuitBreakerConfig defines how the circuit breaker should behave.
	CircuitBreakerConfig breaker.Config
	// FIPS means FedRAMP/FIPS 140-2 compliant configuration was requested.
	FIPS bool
}

func (r *RegisterParams) setDefaults() {
	if r.Clock == nil {
		r.Clock = clockwork.NewRealClock()
	}
}

// CredGetter is an interface for a client that can be used to get host
// credentials. This interface is needed because lib/client can not be imported
// in lib/auth due to circular imports.
type HostCredentials func(context.Context, string, bool, types.RegisterUsingTokenRequest) (*proto.Certs, error)

// Register is used to generate host keys when a node or proxy are running on
// different hosts than the auth server. This method requires provisioning
// tokens to prove a valid auth server was used to issue the joining request
// as well as a method for the node to validate the auth server.
func Register(params RegisterParams) (*proto.Certs, error) {
	params.setDefaults()
	// Read in the token. The token can either be passed in or come from a file
	// on disk.
	token, err := utils.TryReadValueAsFile(params.Token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	log.WithField("auth-servers", params.Servers).Debugf("Registering node to the cluster.")

	type registerMethod struct {
		call func(token string, params RegisterParams) (*proto.Certs, error)
		desc string
	}
	registerThroughAuth := registerMethod{registerThroughAuth, "with auth server"}
	registerThroughProxy := registerMethod{registerThroughProxy, "via proxy server"}

	registerMethods := []registerMethod{registerThroughAuth, registerThroughProxy}
	if params.GetHostCredentials == nil {
		log.Debugf("Missing client, it is not possible to register through proxy.")
		registerMethods = []registerMethod{registerThroughAuth}
	} else if authServerIsProxy(params.Servers) {
		log.Debugf("The first specified auth server appears to be a proxy.")
		registerMethods = []registerMethod{registerThroughProxy, registerThroughAuth}
	}

	var collectedErrs []error
	for _, method := range registerMethods {
		log.Infof("Attempting registration %s.", method.desc)
		certs, err := method.call(token, params)
		if err != nil {
			collectedErrs = append(collectedErrs, err)
			log.WithError(err).Debugf("Registration %s failed.", method.desc)
			continue
		}
		log.Infof("Successfully registered %s.", method.desc)
		return certs, nil
	}
	return nil, trace.NewAggregate(collectedErrs...)
}

// authServerIsProxy returns true if the first specified auth server
// to register with appears to be a proxy.
func authServerIsProxy(servers []utils.NetAddr) bool {
	if len(servers) == 0 {
		return false
	}
	port := servers[0].Port(0)
	return port == defaults.HTTPListenPort || port == teleport.StandardHTTPSPort
}

// registerThroughProxy is used to register through the proxy server.
func registerThroughProxy(token string, params RegisterParams) (*proto.Certs, error) {
	if len(params.Servers) == 0 {
		return nil, trace.BadParameter("no auth servers set")
	}

	var certs *proto.Certs
	// non-IAM join methods use GetHostCredentials function passed through
	// params to call proxy HTTP endpoint
	var err error
	certs, err = params.GetHostCredentials(context.Background(),
		params.Servers[0].String(),
		lib.IsInsecureDevMode(),
		types.RegisterUsingTokenRequest{
			Token:                token,
			HostID:               params.ID.HostUUID,
			NodeName:             params.ID.NodeName,
			Role:                 params.ID.Role,
			AdditionalPrincipals: params.AdditionalPrincipals,
			DNSNames:             params.DNSNames,
			PublicTLSKey:         params.PublicTLSKey,
			PublicSSHKey:         params.PublicSSHKey,
			// EC2IdentityDocument:  params.ec2IdentityDocument,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return certs, nil
}

// registerThroughAuth is used to register through the auth server.
func registerThroughAuth(token string, params RegisterParams) (*proto.Certs, error) {
	var client *Client
	var err error

	// Build a client to the Auth Server. If a CA pin is specified require the
	// Auth Server is validated. Otherwise attempt to use the CA file on disk
	// but if it's not available connect without validating the Auth Server CA.
	switch {
	case len(params.CAPins) != 0:
		client, err = pinRegisterClient(params)
	default:
		client, err = insecureRegisterClient(params)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer client.Close()

	var certs *proto.Certs
	// non-IAM join methods use HTTP endpoint
	// Get the SSH and X509 certificates for a node.
	certs, err = client.RegisterUsingToken(
		context.Background(),
		&types.RegisterUsingTokenRequest{
			Token:                token,
			HostID:               params.ID.HostUUID,
			NodeName:             params.ID.NodeName,
			Role:                 params.ID.Role,
			AdditionalPrincipals: params.AdditionalPrincipals,
			DNSNames:             params.DNSNames,
			PublicTLSKey:         params.PublicTLSKey,
			PublicSSHKey:         params.PublicSSHKey,
			// EC2IdentityDocument:  params.ec2IdentityDocument,
		})
	return certs, trace.Wrap(err)
}

// insecureRegisterClient attempts to connects to the Auth Server using the
// CA on disk. If no CA is found on disk, Teleport will not verify the Auth
// Server it is connecting to.
func insecureRegisterClient(params RegisterParams) (*Client, error) {
	tlsConfig := utils.TLSConfig(params.CipherSuites)
	tlsConfig.Time = params.Clock.Now

	cert, err := readCA(params.CAPath)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	// If no CA was found, then create a insecure connection to the Auth Server,
	// otherwise use the CA on disk to validate the Auth Server.
	if trace.IsNotFound(err) {
		tlsConfig.InsecureSkipVerify = true

		log.Warnf("Joining cluster without validating the identity of the Auth " +
			"Server. This may open you up to a Man-In-The-Middle (MITM) attack if an " +
			"attacker can gain privileged network access. To remedy this, use the CA pin " +
			"value provided when join token was generated to validate the identity of " +
			"the Auth Server.")
	} else {
		certPool := x509.NewCertPool()
		certPool.AddCert(cert)
		tlsConfig.RootCAs = certPool

		log.Infof("Joining remote cluster %v, validating connection with certificate on disk.", cert.Subject.CommonName)
	}

	client, err := NewClient(client.Config{
		Addrs: utils.NetAddrsToStrings(params.Servers),
		Credentials: []client.Credentials{
			client.LoadTLS(tlsConfig),
		},
		CircuitBreakerConfig: params.CircuitBreakerConfig,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return client, nil
}

// readCA will read in CA that will be used to validate the certificate that
// the Auth Server presents.
func readCA(path string) (*x509.Certificate, error) {
	certBytes, err := utils.ReadPath(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert, err := tlsca.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse certificate at %v", path)
	}
	return cert, nil
}

// pinRegisterClient first connects to the Auth Server using a insecure
// connection to fetch the root CA. If the root CA matches the provided CA
// pin, a connection will be re-established and the root CA will be used to
// validate the certificate presented. If both conditions hold true, then we
// know we are connecting to the expected Auth Server.
func pinRegisterClient(params RegisterParams) (*Client, error) {
	// Build a insecure client to the Auth Server. This is safe because even if
	// an attacker were to MITM this connection the CA pin will not match below.
	tlsConfig := utils.TLSConfig(params.CipherSuites)
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.Time = params.Clock.Now
	authClient, err := NewClient(client.Config{
		Addrs: utils.NetAddrsToStrings(params.Servers),
		Credentials: []client.Credentials{
			client.LoadTLS(tlsConfig),
		},
		CircuitBreakerConfig: params.CircuitBreakerConfig,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer authClient.Close()

	// Fetch the root CA from the Auth Server. The NOP role has access to the
	// GetClusterCACert endpoint.
	localCA, err := authClient.GetClusterCACert(context.TODO())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := tlsca.ParseCertificatePEMs(localCA.TLSCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check that the SPKI pin matches the CA we fetched over a insecure
	// connection. This makes sure the CA fetched over a insecure connection is
	// in-fact the expected CA.
	err = utils.CheckSPKI(params.CAPins, certs)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, cert := range certs {
		// Check that the fetched CA is valid at the current time.
		err = utils.VerifyCertificateExpiry(cert, params.Clock)
		if err != nil {
			return nil, trace.Wrap(err)
		}

	}
	log.Infof("Joining remote cluster %v with CA pin.", certs[0].Subject.CommonName)

	// Create another client, but this time with the CA provided to validate
	// that the Auth Server was issued a certificate by the same CA.
	tlsConfig = utils.TLSConfig(params.CipherSuites)
	tlsConfig.Time = params.Clock.Now
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	tlsConfig.RootCAs = certPool

	authClient, err = NewClient(client.Config{
		Addrs: utils.NetAddrsToStrings(params.Servers),
		Credentials: []client.Credentials{
			client.LoadTLS(tlsConfig),
		},
		CircuitBreakerConfig: params.CircuitBreakerConfig,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return authClient, nil
}

// ReRegisterParams specifies parameters for re-registering
// in the cluster (rotating certificates for existing members)
type ReRegisterParams struct {
	// Client is an authenticated client using old credentials
	Client ClientI
	// ID is identity ID
	ID IdentityID
	// AdditionalPrincipals is a list of additional principals to dial
	AdditionalPrincipals []string
	// DNSNames is a list of DNS Names to add to the x509 client certificate
	DNSNames []string
	// PrivateKey is a PEM encoded private key (not passed to auth servers)
	PrivateKey []byte
	// PublicTLSKey is a server's public key to sign
	PublicTLSKey []byte
	// PublicSSHKey is a server's public SSH key to sign
	PublicSSHKey []byte
	// Rotation is the rotation state of the certificate authority
	Rotation types.Rotation
	// SystemRoles is a set of additional system roles held by the instance.
	SystemRoles []types.SystemRole
	// Used by older instances to requisition a multi-role cert by individually
	// proving which system roles are held.
	UnstableSystemRoleAssertionID string
}

// ReRegister renews the certificates and private keys based on the client's existing identity.
func ReRegister(params ReRegisterParams) (*Identity, error) {
	certs, err := params.Client.GenerateHostCerts(context.Background(),
		&proto.HostCertsRequest{
			HostID:                        params.ID.HostID(),
			NodeName:                      params.ID.NodeName,
			Role:                          params.ID.Role,
			AdditionalPrincipals:          params.AdditionalPrincipals,
			DNSNames:                      params.DNSNames,
			PublicTLSKey:                  params.PublicTLSKey,
			PublicSSHKey:                  params.PublicSSHKey,
			Rotation:                      &params.Rotation,
			SystemRoles:                   params.SystemRoles,
			UnstableSystemRoleAssertionID: params.UnstableSystemRoleAssertionID,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ReadIdentityFromKeyPair(params.PrivateKey, certs)
}
