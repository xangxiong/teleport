/*
Copyright 2017-2019 Gravitational, Inc.

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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strconv"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/types/wrappers"
)

// CertAuthority is X.509 certificate authority
type CertAuthority struct {
	// Cert is a CA certificate
	Cert *x509.Certificate
	// Signer is a private key based signer
	Signer crypto.Signer
}

// Identity is an identity of the user or service, e.g. Proxy or Node
type Identity struct {
	// Username is a username or name of the node connection
	Username string
	// Impersonator is a username of a user impersonating this user
	Impersonator string
	// Groups is a list of groups (Teleport roles) encoded in the identity
	Groups []string
	// SystemRoles is a list of system roles (e.g. auth, proxy, node, etc) used
	// in "multi-role" certificates. Single-role certificates encode the system role
	// in `Groups` for back-compat reasons.
	SystemRoles []string
	// Usage is a list of usage restrictions encoded in the identity
	Usage []string
	// Principals is a list of Unix logins allowed.
	Principals []string
	// Expires specifies whenever the session will expire
	Expires time.Time
	// RouteToCluster specifies the target cluster
	// if present in the session
	RouteToCluster string
	// Traits hold claim data used to populate a role at runtime.
	Traits wrappers.Traits
	// TeleportCluster is the name of the teleport cluster that this identity
	// originated from. For TLS certs this may not be the same as cert issuer,
	// in case of multi-hop requests that originate from a remote cluster.
	TeleportCluster string
	// MFAVerified is the UUID of an MFA device when this Identity was
	// confirmed immediately after an MFA check.
	MFAVerified string
	// ClientIP is an observed IP of the client that this Identity represents.
	ClientIP string
	// ActiveRequests is a list of UUIDs of active requests for this Identity.
	ActiveRequests []string
	// DisallowReissue is a flag that, if set, instructs the auth server to
	// deny any attempts to reissue new certificates while authenticated with
	// this certificate.
	DisallowReissue bool
	// Renewable indicates that this identity is allowed to renew it's
	// own credentials. This is only enabled for certificate renewal bots.
	Renewable bool
	// Generation counts the number of times this certificate has been renewed.
	Generation uint64
	// AllowedResourceIDs lists the resources the identity should be allowed to
	// access.
	AllowedResourceIDs []types.ResourceID
}

// CheckAndSetDefaults checks and sets default values
func (id *Identity) CheckAndSetDefaults() error {
	if id.Username == "" {
		return trace.BadParameter("missing identity username")
	}
	if len(id.Groups) == 0 {
		return trace.BadParameter("missing identity groups")
	}

	return nil
}

// Custom ranges are taken from this article
//
// https://serverfault.com/questions/551477/is-there-reserved-oid-space-for-internal-enterprise-cas
//
// http://oid-info.com/get/1.3.9999
var (
	// TeleportClusterASN1ExtensionOID is an extension ID used when encoding/decoding
	// origin teleport cluster name into certificates.
	TeleportClusterASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 7}

	// MFAVerifiedASN1ExtensionOID is an extension ID used when encoding/decoding
	// the MFAVerified flag into certificates.
	MFAVerifiedASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 8}

	// ClientIPASN1ExtensionOID is an extension ID used when encoding/decoding
	// the client IP into certificates.
	ClientIPASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 9}

	// RenewableCertificateASN1ExtensionOID is an extension ID used to indicate
	// that a certificate may be renewed by a certificate renewal bot.
	RenewableCertificateASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 13}

	// GenerationASN1ExtensionOID is an extension OID used to count the number
	// of times this certificate has been renewed.
	GenerationASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 14}

	// ImpersonatorASN1ExtensionOID is an extension OID used when encoding/decoding
	// impersonator user
	ImpersonatorASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 7}

	// ActiveRequestsASN1ExtensionOID is an extension OID used when encoding/decoding
	// active access requests into certificates.
	ActiveRequestsASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 8}

	// DisallowReissueASN1ExtensionOID is an extension OID used to flag that a
	// requests to generate new certificates using this certificate should be
	// denied.
	DisallowReissueASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 9}

	// AllowedResourcesASN1ExtensionOID is an extension OID used to list the
	// resources which the certificate should be able to grant access to
	AllowedResourcesASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 10}

	// SystemRolesASN1ExtensionOID is an extension OID used to indicate system roles
	// (auth, proxy, node, etc). Note that some certs correspond to a single specific
	// system role, and use `pkix.Name.Organization` to encode this value. This extension
	// is specifically used for "multi-role" certs.
	SystemRolesASN1ExtensionOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 11}
)

// FromSubject returns identity from subject name
func FromSubject(subject pkix.Name, expires time.Time) (*Identity, error) {
	id := &Identity{
		Username:   subject.CommonName,
		Groups:     subject.Organization,
		Usage:      subject.OrganizationalUnit,
		Principals: subject.Locality,
		Expires:    expires,
	}
	if len(subject.StreetAddress) > 0 {
		id.RouteToCluster = subject.StreetAddress[0]
	}
	if len(subject.PostalCode) > 0 {
		err := wrappers.UnmarshalTraits([]byte(subject.PostalCode[0]), &id.Traits)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	for _, attr := range subject.Names {
		switch {
		case attr.Type.Equal(SystemRolesASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.SystemRoles = append(id.SystemRoles, val)
			}
		case attr.Type.Equal(RenewableCertificateASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.Renewable = val == types.True
			}
		case attr.Type.Equal(TeleportClusterASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.TeleportCluster = val
			}
		case attr.Type.Equal(MFAVerifiedASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.MFAVerified = val
			}
		case attr.Type.Equal(ClientIPASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.ClientIP = val
			}
		case attr.Type.Equal(ImpersonatorASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.Impersonator = val
			}
		case attr.Type.Equal(ActiveRequestsASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.ActiveRequests = append(id.ActiveRequests, val)
			}
		case attr.Type.Equal(DisallowReissueASN1ExtensionOID):
			val, ok := attr.Value.(string)
			if ok {
				id.DisallowReissue = val == types.True
			}
		case attr.Type.Equal(GenerationASN1ExtensionOID):
			// This doesn't seem to play nice with int types, so we'll parse it
			// from a string.
			val, ok := attr.Value.(string)
			if ok {
				generation, err := strconv.ParseUint(val, 10, 64)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				id.Generation = generation
			}
		case attr.Type.Equal(AllowedResourcesASN1ExtensionOID):
			allowedResourcesStr, ok := attr.Value.(string)
			if ok {
				allowedResourceIDs, err := types.ResourceIDsFromString(allowedResourcesStr)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				id.AllowedResourceIDs = allowedResourceIDs
			}
		}
	}

	if err := id.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return id, nil
}

func (id Identity) GetUserMetadata() events.UserMetadata {
	return events.UserMetadata{
		User:           id.Username,
		Impersonator:   id.Impersonator,
		AccessRequests: id.ActiveRequests,
	}
}
