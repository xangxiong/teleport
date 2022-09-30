/*
Copyright 2017-2021 Gravitational, Inc.

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
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
)

// ErrOIDCNoRoles results from not mapping any roles from OIDC claims.
var ErrOIDCNoRoles = trace.AccessDenied("No roles mapped from claims. The mappings may contain typos.")

// OIDCAuthResponse is returned when auth server validated callback parameters
// returned from OIDC provider
type OIDCAuthResponse struct {
	// Username is authenticated teleport username
	Username string `json:"username"`
	// Identity contains validated OIDC identity
	Identity types.ExternalIdentity `json:"identity"`
	// Web session will be generated by auth server if requested in OIDCAuthRequest
	Session types.WebSession `json:"session,omitempty"`
	// Cert will be generated by certificate authority
	Cert []byte `json:"cert,omitempty"`
	// TLSCert is PEM encoded TLS certificate
	TLSCert []byte `json:"tls_cert,omitempty"`
	// Req is original oidc auth request
	Req types.OIDCAuthRequest `json:"req"`
	// HostSigners is a list of signing host public keys
	// trusted by proxy, used in console login
	HostSigners []types.CertAuthority `json:"host_signers"`
}

// claimsFromIDToken extracts claims from the ID token.
func claimsFromIDToken(oidcClient *oidc.Client, idToken string) (jose.Claims, error) {
	jwt, err := jose.ParseJWT(idToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = oidcClient.VerifyJWT(jwt)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	log.Debugf("Extracting OIDC claims from ID token.")

	claims, err := jwt.Claims()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return claims, nil
}

// claimsFromUserInfo finds the UserInfo endpoint from the provider config and then extracts claims from it.
//
// Note: We don't request signed JWT responses for UserInfo, instead we force the provider config and
// the issuer to be HTTPS and leave integrity and confidentiality to TLS. Authenticity is taken care of
// during the token exchange.
func claimsFromUserInfo(oidcClient *oidc.Client, issuerURL string, accessToken string) (jose.Claims, error) {
	// If the issuer URL is not HTTPS, return the error as trace.NotFound to
	// allow the caller to treat this condition gracefully and extract claims
	// just from the token.
	err := isHTTPS(issuerURL)
	if err != nil {
		return nil, trace.NotFound(err.Error())
	}

	oac, err := oidcClient.OAuthClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	hc := oac.HttpClient()

	// go get the provider config so we can find out where the UserInfo endpoint
	// is. if the provider doesn't offer a UserInfo endpoint return not found.
	pc, err := oidc.FetchProviderConfig(oac.HttpClient(), issuerURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if pc.UserInfoEndpoint == nil {
		return nil, trace.NotFound("UserInfo endpoint not found")
	}

	endpoint := pc.UserInfoEndpoint.String()

	// If the userinfo endpoint is not HTTPS, return the error as trace.NotFound to
	// allow the caller to treat this condition gracefully and extract claims
	// just from the token.
	err = isHTTPS(endpoint)
	if err != nil {
		return nil, trace.NotFound(err.Error())
	}
	log.Debugf("Fetching OIDC claims from UserInfo endpoint: %q.", endpoint)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := hc.Do(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	if code < 200 || code > 299 {
		// These are expected userinfo failures.
		if code == http.StatusBadRequest || code == http.StatusUnauthorized ||
			code == http.StatusForbidden || code == http.StatusMethodNotAllowed {
			return nil, trace.AccessDenied("bad status code: %v", code)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return nil, trace.ReadError(code, body)
	}

	var claims jose.Claims
	err = json.NewDecoder(resp.Body).Decode(&claims)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return claims, nil
}

// mergeClaims merges b into a.
func mergeClaims(a jose.Claims, b jose.Claims) (jose.Claims, error) {
	for k, v := range b {
		_, ok := a[k]
		if !ok {
			a[k] = v
		}
	}

	return a, nil
}

// getClaims implements Server.getClaims, but allows that code path to be overridden for testing.
func getClaims(closeCtx context.Context, oidcClient *oidc.Client, connector types.OIDCConnector, code string) (jose.Claims, error) {
	oac, err := getOAuthClient(oidcClient, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	t, err := oac.RequestToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		if e, ok := err.(*oauth2.Error); ok {
			if e.Type == oauth2.ErrorAccessDenied {
				return nil, trace.Wrap(err, "the client_id and/or client_secret may be incorrect")
			}
		}
		return nil, trace.Wrap(err)
	}

	idTokenClaims, err := claimsFromIDToken(oidcClient, t.IDToken)
	if err != nil {
		log.Debugf("Unable to fetch OIDC ID token claims: %v.", err)
		return nil, trace.Wrap(err, "unable to fetch OIDC ID token claims")
	}
	log.Debugf("OIDC ID Token claims: %v.", idTokenClaims)

	userInfoClaims, err := claimsFromUserInfo(oidcClient, connector.GetIssuerURL(), t.AccessToken)
	if err != nil {
		if trace.IsNotFound(err) {
			log.Debugf("OIDC provider doesn't offer valid UserInfo endpoint. Returning token claims: %v.", idTokenClaims)
			return idTokenClaims, nil
		}
		// This captures 400, 401, 403, and 405.
		if trace.IsAccessDenied(err) {
			log.Debugf("UserInfo endpoint returned an error: %v. Returning token claims: %v.", err, idTokenClaims)
			return idTokenClaims, nil
		}
		log.Debugf("Unable to fetch UserInfo claims: %v.", err)
		return nil, trace.Wrap(err, "unable to fetch UserInfo claims")
	}
	log.Debugf("UserInfo claims: %v.", userInfoClaims)

	// make sure that the subject in the userinfo claim matches the subject in
	// the id token otherwise there is the possibility of a token substitution attack.
	// see section 16.11 of the oidc spec for more details.
	var idsub string
	var uisub string
	var exists bool
	if idsub, exists, err = idTokenClaims.StringClaim("sub"); err != nil || !exists {
		log.Debugf("Unable to extract OIDC sub claim from ID token.")
		return nil, trace.Wrap(err, "unable to extract OIDC sub claim from ID token")
	}
	if uisub, exists, err = userInfoClaims.StringClaim("sub"); err != nil || !exists {
		log.Debugf("Unable to extract OIDC sub claim from UserInfo.")
		return nil, trace.Wrap(err, "unable to extract OIDC sub claim from UserInfo")
	}
	if idsub != uisub {
		log.Debugf("OIDC claim subjects don't match '%v' != '%v'.", idsub, uisub)
		return nil, trace.BadParameter("OIDC claim subjects in UserInfo does not match")
	}

	claims, err := mergeClaims(idTokenClaims, userInfoClaims)
	if err != nil {
		log.Debugf("Unable to merge OIDC claims: %v.", err)
		return nil, trace.Wrap(err, "unable to merge OIDC claims")
	}

	if isGoogleWorkspaceConnector(connector) {
		claims, err = addGoogleWorkspaceClaims(closeCtx, connector, claims)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return claims, nil
}

// getOAuthClient returns a Oauth2 client from the oidc.Client.  If the connector is set as a Ping provider sets the Client Secret Post auth method
func getOAuthClient(oidcClient *oidc.Client, connector types.OIDCConnector) (*oauth2.Client, error) {
	oac, err := oidcClient.OAuthClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// For OIDC, Ping and Okta will throw an error when the
	// default client secret basic method is used.
	// See: https://github.com/gravitational/teleport/issues/8374
	switch connector.GetProvider() {
	case teleport.Ping, teleport.Okta:
		oac.SetAuthMethod(oauth2.AuthMethodClientSecretPost)
	}

	return oac, err
}
