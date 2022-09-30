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

// Package services implements API services exposed by Teleport:
// * presence service that takes care of heartbeats
// * web service that takes care of web logins
// * ca service - certificate authorities
package services

import (
	"context"

	"github.com/gravitational/teleport/api/types"
	wantypes "github.com/gravitational/teleport/api/types/webauthn"
	"github.com/gravitational/teleport/lib/defaults"

	"github.com/gravitational/trace"
)

// Identity is responsible for managing user entries and external identities
type Identity interface {
	// UpsertWebauthnLocalAuth creates or updates the local auth configuration for
	// Webauthn.
	// WebauthnLocalAuth is a component of LocalAuthSecrets.
	// Automatically indexes the WebAuthn user ID for lookup by
	// GetTeleportUserByWebauthnID.
	UpsertWebauthnLocalAuth(ctx context.Context, user string, wla *types.WebauthnLocalAuth) error

	// GetWebauthnLocalAuth retrieves the existing local auth configuration for
	// Webauthn, if any.
	// WebauthnLocalAuth is a component of LocalAuthSecrets.
	GetWebauthnLocalAuth(ctx context.Context, user string) (*types.WebauthnLocalAuth, error)

	// GetTeleportUserByWebauthnID reads a Teleport username from a WebAuthn user
	// ID (aka user handle).
	// See UpsertWebauthnLocalAuth and types.WebauthnLocalAuth.
	GetTeleportUserByWebauthnID(ctx context.Context, webID []byte) (string, error)

	// UpsertWebauthnSessionData creates or updates WebAuthn session data in
	// storage, for the purpose of later verifying an authentication or
	// registration challenge.
	// Session data is expected to expire according to backend settings.
	UpsertWebauthnSessionData(ctx context.Context, user, sessionID string, sd *wantypes.SessionData) error

	// GetWebauthnSessionData retrieves a previously-stored session data by ID,
	// if it exists and has not expired.
	GetWebauthnSessionData(ctx context.Context, user, sessionID string) (*wantypes.SessionData, error)

	// DeleteWebauthnSessionData deletes session data by ID, if it exists and has
	// not expired.
	DeleteWebauthnSessionData(ctx context.Context, user, sessionID string) error

	// UpsertGlobalWebauthnSessionData creates or updates WebAuthn session data in
	// storage, for the purpose of later verifying an authentication challenge.
	// Session data is expected to expire according to backend settings.
	// Used for passwordless challenges.
	UpsertGlobalWebauthnSessionData(ctx context.Context, scope, id string, sd *wantypes.SessionData) error

	// GetGlobalWebauthnSessionData retrieves previously-stored session data by ID,
	// if it exists and has not expired.
	// Used for passwordless challenges.
	GetGlobalWebauthnSessionData(ctx context.Context, scope, id string) (*wantypes.SessionData, error)

	// DeleteGlobalWebauthnSessionData deletes session data by ID, if it exists
	// and has not expired.
	DeleteGlobalWebauthnSessionData(ctx context.Context, scope, id string) error

	// UpsertMFADevice upserts an MFA device for the user.
	UpsertMFADevice(ctx context.Context, user string, d *types.MFADevice) error

	// GetMFADevices gets all MFA devices for the user.
	GetMFADevices(ctx context.Context, user string, withSecrets bool) ([]*types.MFADevice, error)

	// DeleteMFADevice deletes an MFA device for the user by ID.
	DeleteMFADevice(ctx context.Context, user, id string) error

	// CreateSSODiagnosticInfo creates new SSO diagnostic info record.
	CreateSSODiagnosticInfo(ctx context.Context, authKind string, authRequestID string, entry types.SSODiagnosticInfo) error

	// GetSSODiagnosticInfo returns SSO diagnostic info records.
	GetSSODiagnosticInfo(ctx context.Context, authKind string, authRequestID string) (*types.SSODiagnosticInfo, error)

	// CreateUserToken creates a new user token.
	CreateUserToken(ctx context.Context, token types.UserToken) (types.UserToken, error)

	// DeleteUserToken deletes a user token.
	DeleteUserToken(ctx context.Context, tokenID string) error

	// GetUserTokens returns all user tokens.
	GetUserTokens(ctx context.Context) ([]types.UserToken, error)

	// GetUserToken returns a user token by id.
	GetUserToken(ctx context.Context, tokenID string) (types.UserToken, error)

	// UpsertUserTokenSecrets upserts a user token secrets.
	UpsertUserTokenSecrets(ctx context.Context, secrets types.UserTokenSecrets) error

	// GetUserTokenSecrets returns a user token secrets.
	GetUserTokenSecrets(ctx context.Context, tokenID string) (types.UserTokenSecrets, error)

	// UpsertRecoveryCodes upserts a user's new recovery codes.
	UpsertRecoveryCodes(ctx context.Context, user string, recovery *types.RecoveryCodesV1) error

	// GetRecoveryCodes gets a user's recovery codes.
	GetRecoveryCodes(ctx context.Context, user string, withSecrets bool) (*types.RecoveryCodesV1, error)

	// CreateUserRecoveryAttempt logs user recovery attempt.
	CreateUserRecoveryAttempt(ctx context.Context, user string, attempt *types.RecoveryAttempt) error

	// GetUserRecoveryAttempts returns user recovery attempts sorted by oldest to latest time.
	GetUserRecoveryAttempts(ctx context.Context, user string) ([]*types.RecoveryAttempt, error)

	// DeleteUserRecoveryAttempts removes all recovery attempts of a user.
	DeleteUserRecoveryAttempts(ctx context.Context, user string) error

	types.WebTokensGetter
}

// VerifyPassword makes sure password satisfies our requirements (relaxed),
// mostly to avoid putting garbage in
func VerifyPassword(password []byte) error {
	if len(password) < defaults.MinPasswordLength {
		return trace.BadParameter(
			"password is too short, min length is %v", defaults.MinPasswordLength)
	}
	if len(password) > defaults.MaxPasswordLength {
		return trace.BadParameter(
			"password is too long, max length is %v", defaults.MaxPasswordLength)
	}
	return nil
}

// Users represents a slice of users,
// makes it sort compatible (sorts by username)
type Users []types.User

func (u Users) Len() int {
	return len(u)
}

func (u Users) Less(i, j int) bool {
	return u[i].GetName() < u[j].GetName()
}

func (u Users) Swap(i, j int) {
	u[i], u[j] = u[j], u[i]
}

// SortedLoginAttempts sorts login attempts by time
type SortedLoginAttempts []LoginAttempt

// Len returns length of a role list
func (s SortedLoginAttempts) Len() int {
	return len(s)
}

// Less stacks latest attempts to the end of the list
func (s SortedLoginAttempts) Less(i, j int) bool {
	return s[i].Time.Before(s[j].Time)
}

// Swap swaps two attempts
func (s SortedLoginAttempts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// LastFailed calculates last x successive attempts are failed
func LastFailed(x int, attempts []LoginAttempt) bool {
	var failed int
	for i := len(attempts) - 1; i >= 0; i-- {
		if !attempts[i].Success {
			failed++
		} else {
			return false
		}
		if failed >= x {
			return true
		}
	}
	return false
}
