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

package auth

import (
	"context"
	"errors"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// AuthenticateUserRequest is a request to authenticate interactive user
type AuthenticateUserRequest struct {
	// Username is a username
	Username string `json:"username"`
	// Pass is a password used in local authentication schemes
	Pass *PassCreds `json:"pass,omitempty"`
	// Webauthn is a signed credential assertion, used in MFA authentication
	Webauthn *wanlib.CredentialAssertionResponse `json:"webauthn,omitempty"`
	// OTP is a password and second factor, used for MFA authentication
	OTP *OTPCreds `json:"otp,omitempty"`
	// Session is a web session credential used to authenticate web sessions
	Session *SessionCreds `json:"session,omitempty"`
	// ClientMetadata includes forwarded information about a client
	ClientMetadata *ForwardedClientMetadata `json:"client_metadata,omitempty"`
}

// ForwardedClientMetadata can be used by the proxy web API to forward information about
// the client to the auth service for logging purposes.
type ForwardedClientMetadata struct {
	UserAgent  string `json:"user_agent,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

// CheckAndSetDefaults checks and sets defaults
func (a *AuthenticateUserRequest) CheckAndSetDefaults() error {
	switch {
	case a.Username == "" && a.Webauthn != nil: // OK, passwordless.
	case a.Username == "":
		return trace.BadParameter("missing parameter 'username'")
	case a.Pass == nil && a.Webauthn == nil && a.OTP == nil && a.Session == nil:
		return trace.BadParameter("at least one authentication method is required")
	}
	return nil
}

// PassCreds is a password credential
type PassCreds struct {
	// Password is a user password
	Password []byte `json:"password"`
}

// OTPCreds is a two-factor authentication credentials
type OTPCreds struct {
	// Password is a user password
	Password []byte `json:"password"`
	// Token is a user second factor token
	Token string `json:"token"`
}

// SessionCreds is a web session credentials
type SessionCreds struct {
	// ID is a web session id
	ID string `json:"id"`
}

var (
	// authenticateWebauthnError is the generic error returned for failed WebAuthn
	// authentication attempts.
	authenticateWebauthnError = trace.AccessDenied("invalid Webauthn response")
	// invalidUserPassError is the error for when either the provided username or
	// password is incorrect.
	invalidUserPassError = trace.AccessDenied("invalid username or password")
	// invalidUserpass2FError is the error for when either the provided username,
	// password, or second factor is incorrect.
	invalidUserPass2FError = trace.AccessDenied("invalid username, password or second factor")
)

// IsInvalidLocalCredentialError checks if an error resulted from an incorrect username,
// password, or second factor.
func IsInvalidLocalCredentialError(err error) bool {
	return errors.Is(err, invalidUserPassError) || errors.Is(err, invalidUserPass2FError)
}

func (s *Server) authenticatePasswordless(ctx context.Context, req AuthenticateUserRequest) (*types.MFADevice, string, error) {
	mfaResponse := &proto.MFAAuthenticateResponse{
		Response: &proto.MFAAuthenticateResponse_Webauthn{
			Webauthn: wanlib.CredentialAssertionResponseToProto(req.Webauthn),
		},
	}
	dev, user, err := s.validateMFAAuthResponse(ctx, mfaResponse, "", true /* passwordless */)
	if err != nil {
		log.Debugf("Passwordless authentication failed: %v", err)
		return nil, "", trace.Wrap(authenticateWebauthnError)
	}

	// A distinction between passwordless and "plain" MFA is that we can't
	// acquire the user lock beforehand (or at all on failures!)
	// We do grab it here so successful logins go through the regular process.
	if err := s.WithUserLock(user, func() error { return nil }); err != nil {
		log.Debugf("WithUserLock for user %q failed during passwordless authentication: %v", user, err)
		return nil, user, trace.Wrap(authenticateWebauthnError)
	}

	return dev, user, nil
}

// // AuthenticateWebUser authenticates web user, creates and returns a web session
// // if authentication is successful. In case the existing session ID is used to authenticate,
// // returns the existing session instead of creating a new one
// func (s *Server) AuthenticateWebUser(ctx context.Context, req AuthenticateUserRequest) (types.WebSession, error) {
// 	username := req.Username // Empty if passwordless.

// 	authPref, err := s.GetAuthPreference(ctx)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	// Disable all local auth requests,
// 	// except session ID renewal requests that are using the same method.
// 	// This condition uses Session as a blanket check, because any new method added
// 	// to the local auth will be disabled by default.
// 	if !authPref.GetAllowLocalAuth() && req.Session == nil {
// 		s.emitNoLocalAuthEvent(username)
// 		return nil, trace.AccessDenied(noLocalAuth)
// 	}

// 	if req.Session != nil {
// 		session, err := s.GetWebSession(context.TODO(), types.GetWebSessionRequest{
// 			User:      username,
// 			SessionID: req.Session.ID,
// 		})
// 		if err != nil {
// 			return nil, trace.AccessDenied("session is invalid or has expired")
// 		}
// 		return session, nil
// 	}

// 	actualUser, err := s.AuthenticateUser(req)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	username = actualUser

// 	user, err := s.GetUser(username, false /* withSecrets */)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	sess, err := s.createUserWebSession(context.TODO(), user)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	return sess, nil
// }

// AuthenticateSSHRequest is a request to authenticate SSH client user via CLI
type AuthenticateSSHRequest struct {
	// AuthenticateUserRequest is a request with credentials
	AuthenticateUserRequest
	// PublicKey is a public key in ssh authorized_keys format
	PublicKey []byte `json:"public_key"`
	// TTL is a requested TTL for certificates to be issues
	TTL time.Duration `json:"ttl"`
	// CompatibilityMode sets certificate compatibility mode with old SSH clients
	CompatibilityMode string `json:"compatibility_mode"`
	RouteToCluster    string `json:"route_to_cluster"`
	// KubernetesCluster sets the target kubernetes cluster for the TLS
	// certificate. This can be empty on older clients.
	KubernetesCluster string `json:"kubernetes_cluster"`
}

// CheckAndSetDefaults checks and sets default certificate values
func (a *AuthenticateSSHRequest) CheckAndSetDefaults() error {
	if err := a.AuthenticateUserRequest.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if len(a.PublicKey) == 0 {
		return trace.BadParameter("missing parameter 'public_key'")
	}
	certificateFormat, err := utils.CheckCertificateFormatFlag(a.CompatibilityMode)
	if err != nil {
		return trace.Wrap(err)
	}
	a.CompatibilityMode = certificateFormat
	return nil
}

// SSHLoginResponse is a response returned by web proxy, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type SSHLoginResponse struct {
	// User contains a logged-in user information
	Username string `json:"username"`
	// Cert is a PEM encoded  signed certificate
	Cert []byte `json:"cert"`
	// TLSCertPEM is a PEM encoded TLS certificate signed by TLS certificate authority
	TLSCert []byte `json:"tls_cert"`
	// HostSigners is a list of signing host public keys trusted by proxy
	HostSigners []TrustedCerts `json:"host_signers"`
}

// TrustedCerts contains host certificates, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type TrustedCerts struct {
	// ClusterName identifies teleport cluster name this authority serves,
	// for host authorities that means base hostname of all servers,
	// for user authorities that means organization name
	ClusterName string `json:"domain_name"`
	// HostCertificates is a list of SSH public keys that can be used to check
	// host certificate signatures
	HostCertificates [][]byte `json:"checking_keys"`
	// TLSCertificates  is a list of TLS certificates of the certificate authority
	// of the authentication server
	TLSCertificates [][]byte `json:"tls_certs"`
}

// SSHCertPublicKeys returns a list of trusted host SSH certificate authority public keys
func (c *TrustedCerts) SSHCertPublicKeys() ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(c.HostCertificates))
	for _, keyBytes := range c.HostCertificates {
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, publicKey)
	}
	return out, nil
}

// AuthoritiesToTrustedCerts serializes authorities to TrustedCerts data structure
func AuthoritiesToTrustedCerts(authorities []types.CertAuthority) []TrustedCerts {
	out := make([]TrustedCerts, len(authorities))
	for i, ca := range authorities {
		out[i] = TrustedCerts{
			ClusterName:      ca.GetClusterName(),
			HostCertificates: services.GetSSHCheckingKeys(ca),
			TLSCertificates:  services.GetTLSCerts(ca),
		}
	}
	return out
}

// emitNoLocalAuthEvent creates and emits a local authentication is disabled message.
func (s *Server) emitNoLocalAuthEvent(username string) {
	if err := s.emitter.EmitAuditEvent(s.closeCtx, &apievents.AuthAttempt{
		Metadata: apievents.Metadata{
			Type: events.AuthAttemptEvent,
			Code: events.AuthAttemptFailureCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: username,
		},
		Status: apievents.Status{
			Success: false,
			Error:   noLocalAuth,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit no local auth event.")
	}
}

func (s *Server) createUserWebSession(ctx context.Context, user types.User) (types.WebSession, error) {
	// It's safe to extract the roles and traits directly from services.User as this method
	// is only used for local accounts.
	return s.createWebSession(ctx, types.NewWebSessionRequest{
		User:      user.GetName(),
		Roles:     user.GetRoles(),
		Traits:    user.GetTraits(),
		LoginTime: s.clock.Now().UTC(),
	})
}

func getErrorByTraceField(err error) error {
	traceErr, ok := err.(trace.Error)
	switch {
	case !ok:
		log.WithError(err).Warn("Unexpected error type, wanted TraceError")
		return trace.AccessDenied("an error has occurred")
	case traceErr.GetFields()[ErrFieldKeyUserMaxedAttempts] != nil:
		return trace.AccessDenied(MaxFailedAttemptsErrMsg)
	}

	return nil
}

const noLocalAuth = "local auth disabled"
