/*
Copyright 2020 Gravitational, Inc.

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

// OIDCConnector specifies configuration for Open ID Connect compatible external
// identity provider, e.g. google in some organisation
type OIDCConnector interface {
	// ResourceWithSecrets provides common methods for objects
	ResourceWithSecrets
	// Issuer URL is the endpoint of the provider, e.g. https://accounts.google.com
	GetIssuerURL() string
	// ClientID is id for authentication client (in our case it's our Auth server)
	GetClientID() string
	// ClientSecret is used to authenticate our client and should not
	// be visible to end user
	GetClientSecret() string
	// GetRedirectURLs returns list of redirect URLs.
	GetRedirectURLs() []string
	// GetACR returns the Authentication Context Class Reference (ACR) value.
	GetACR() string
	// GetProvider returns the identity provider.
	GetProvider() string
	// Display - Friendly name for this provider.
	GetDisplay() string
	// Scope is additional scopes set by provider
	GetScope() []string
	// ClaimsToRoles specifies dynamic mapping from claims to roles
	GetClaimsToRoles() []ClaimMapping
	// GetClaims returns list of claims expected by mappings
	GetClaims() []string
	// GetTraitMappings converts gets all claim mappings in the
	// generic trait mapping format.
	GetTraitMappings() TraitMappingSet
	// SetClientSecret sets client secret to some value
	SetClientSecret(secret string)
	// SetClientID sets id for authentication client (in our case it's our Auth server)
	SetClientID(string)
	// SetIssuerURL sets the endpoint of the provider
	SetIssuerURL(string)
	// SetRedirectURLs sets the list of redirectURLs
	SetRedirectURLs([]string)
	// SetPrompt sets OIDC prompt value
	SetPrompt(string)
	// GetPrompt returns OIDC prompt value,
	GetPrompt() string
	// SetACR sets the Authentication Context Class Reference (ACR) value.
	SetACR(string)
	// SetProvider sets the identity provider.
	SetProvider(string)
	// SetScope sets additional scopes set by provider
	SetScope([]string)
	// SetClaimsToRoles sets dynamic mapping from claims to roles
	SetClaimsToRoles([]ClaimMapping)
	// SetDisplay sets friendly name for this provider.
	SetDisplay(string)
	// GetGoogleServiceAccountURI returns path to google service account URI
	GetGoogleServiceAccountURI() string
	// GetGoogleServiceAccount returns google service account json for Google
	GetGoogleServiceAccount() string
	// SetGoogleServiceAccount sets the google service account json contents
	SetGoogleServiceAccount(string)
	// GetGoogleAdminEmail returns a google admin user email
	// https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority
	// "Note: Although you can use service accounts in applications that run from a Google Workspace (formerly G Suite) domain, service accounts are not members of your Google Workspace account and aren’t subject to domain policies set by  administrators. For example, a policy set in the Google Workspace admin console to restrict the ability of end users to share documents outside of the domain would not apply to service accounts."
	GetGoogleAdminEmail() string
}
