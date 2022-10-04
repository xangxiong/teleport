/*
Copyright 2020-2021 Gravitational, Inc.

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

package types

import (
	"time"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/trace"
)

// SAMLConnector specifies configuration for SAML 2.0 identity providers
type SAMLConnector interface {
	// ResourceWithSecrets provides common methods for objects
	ResourceWithSecrets
}

// GetVersion returns resource version
func (o *SAMLConnectorV2) GetVersion() string {
	return o.Version
}

// GetKind returns resource kind
func (o *SAMLConnectorV2) GetKind() string {
	return o.Kind
}

// GetSubKind returns resource sub kind
func (o *SAMLConnectorV2) GetSubKind() string {
	return o.SubKind
}

// SetSubKind sets resource subkind
func (o *SAMLConnectorV2) SetSubKind(sk string) {
	o.SubKind = sk
}

// GetResourceID returns resource ID
func (o *SAMLConnectorV2) GetResourceID() int64 {
	return o.Metadata.ID
}

// SetResourceID sets resource ID
func (o *SAMLConnectorV2) SetResourceID(id int64) {
	o.Metadata.ID = id
}

// WithoutSecrets returns an instance of resource without secrets.
func (o *SAMLConnectorV2) WithoutSecrets() Resource {
	k1 := o.GetSigningKeyPair()
	k2 := o.GetEncryptionKeyPair()
	o2 := *o
	if k1 != nil {
		q1 := *k1
		q1.PrivateKey = ""
		o2.SetSigningKeyPair(&q1)
	}
	if k2 != nil {
		q2 := *k2
		q2.PrivateKey = ""
		o2.SetEncryptionKeyPair(&q2)
	}
	return &o2
}

// GetMetadata returns object metadata
func (o *SAMLConnectorV2) GetMetadata() Metadata {
	return o.Metadata
}

// SetExpiry sets expiry time for the object
func (o *SAMLConnectorV2) SetExpiry(expires time.Time) {
	o.Metadata.SetExpiry(expires)
}

// Expiry returns object expiry setting
func (o *SAMLConnectorV2) Expiry() time.Time {
	return o.Metadata.Expiry()
}

// GetName returns the name of the connector
func (o *SAMLConnectorV2) GetName() string {
	return o.Metadata.GetName()
}

// SetName sets client secret to some value
func (o *SAMLConnectorV2) SetName(name string) {
	o.Metadata.SetName(name)
}

// GetSigningKeyPair returns signing key pair
func (o *SAMLConnectorV2) GetSigningKeyPair() *AsymmetricKeyPair {
	return o.Spec.SigningKeyPair
}

// SetSigningKeyPair sets signing key pair
func (o *SAMLConnectorV2) SetSigningKeyPair(k *AsymmetricKeyPair) {
	o.Spec.SigningKeyPair = k
}

// GetEncryptionKeyPair returns the key pair for SAML assertions.
func (o *SAMLConnectorV2) GetEncryptionKeyPair() *AsymmetricKeyPair {
	return o.Spec.EncryptionKeyPair
}

// SetEncryptionKeyPair sets the key pair for SAML assertions.
func (o *SAMLConnectorV2) SetEncryptionKeyPair(k *AsymmetricKeyPair) {
	o.Spec.EncryptionKeyPair = k
}

// setStaticFields sets static resource header and metadata fields.
func (o *SAMLConnectorV2) setStaticFields() {
	o.Kind = KindSAMLConnector
	o.Version = V2
}

// CheckAndSetDefaults checks and sets default values
func (o *SAMLConnectorV2) CheckAndSetDefaults() error {
	o.setStaticFields()
	if err := o.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if name := o.Metadata.Name; utils.SliceContainsStr(constants.SystemConnectors, name) {
		return trace.BadParameter("ID: invalid connector name, %v is a reserved name", name)
	}
	if o.Spec.AssertionConsumerService == "" {
		return trace.BadParameter("missing acs - assertion consumer service parameter, set service URL that will receive POST requests from SAML")
	}
	if o.Spec.ServiceProviderIssuer == "" {
		o.Spec.ServiceProviderIssuer = o.Spec.AssertionConsumerService
	}
	if o.Spec.Audience == "" {
		o.Spec.Audience = o.Spec.AssertionConsumerService
	}
	// Issuer and SSO can be automatically set later if EntityDescriptor is provided
	if o.Spec.EntityDescriptorURL == "" && o.Spec.EntityDescriptor == "" && (o.Spec.Issuer == "" || o.Spec.SSO == "") {
		return trace.BadParameter("no entity_descriptor set, either provide entity_descriptor or entity_descriptor_url in spec")
	}
	// make sure claim mappings have either roles or a role template
	for _, v := range o.Spec.AttributesToRoles {
		if len(v.Roles) == 0 {
			return trace.BadParameter("need roles field in attributes_to_roles")
		}
	}
	return nil
}
