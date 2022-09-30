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

package local

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	wantypes "github.com/gravitational/teleport/api/types/webauthn"
)

// GlobalSessionDataMaxEntries represents the maximum number of in-flight
// global WebAuthn challenges for a given scope.
// Attempting to write more instances than the max limit causes an error.
// The limit is enforced separately by Auth Server instances.
var GlobalSessionDataMaxEntries = 5000 // arbitrary

// IdentityService is responsible for managing web users and currently
// user accounts as well
type IdentityService struct {
	backend.Backend
	log logrus.FieldLogger
}

// NewIdentityService returns a new instance of IdentityService object
func NewIdentityService(backend backend.Backend) *IdentityService {
	return &IdentityService{
		Backend: backend,
		log:     logrus.WithField(trace.Component, "identity"),
	}
}

// func webauthnLocalAuthKey(user string) []byte {
// 	return backend.Key(webPrefix, usersPrefix, user, webauthnLocalAuthPrefix)
// }

// func webauthnUserKey(id []byte) []byte {
// 	key := base64.RawURLEncoding.EncodeToString(id)
// 	return backend.Key(webauthnPrefix, usersPrefix, key)
// }

// func (s *IdentityService) UpsertWebauthnSessionData(ctx context.Context, user, sessionID string, sd *wantypes.SessionData) error {
// 	switch {
// 	case user == "":
// 		return trace.BadParameter("missing parameter user")
// 	case sessionID == "":
// 		return trace.BadParameter("missing parameter sessionID")
// 	case sd == nil:
// 		return trace.BadParameter("missing parameter sd")
// 	}

// 	value, err := json.Marshal(sd)
// 	if err != nil {
// 		return trace.Wrap(err)
// 	}
// 	_, err = s.Put(ctx, backend.Item{
// 		Key:     sessionDataKey(user, sessionID),
// 		Value:   value,
// 		Expires: s.Clock().Now().UTC().Add(defaults.WebauthnChallengeTimeout),
// 	})
// 	return trace.Wrap(err)
// }

// func (s *IdentityService) GetWebauthnSessionData(ctx context.Context, user, sessionID string) (*wantypes.SessionData, error) {
// 	switch {
// 	case user == "":
// 		return nil, trace.BadParameter("missing parameter user")
// 	case sessionID == "":
// 		return nil, trace.BadParameter("missing parameter sessionID")
// 	}

// 	item, err := s.Get(ctx, sessionDataKey(user, sessionID))
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	sd := &wantypes.SessionData{}
// 	return sd, trace.Wrap(json.Unmarshal(item.Value, sd))
// }

// func (s *IdentityService) DeleteWebauthnSessionData(ctx context.Context, user, sessionID string) error {
// 	switch {
// 	case user == "":
// 		return trace.BadParameter("missing parameter user")
// 	case sessionID == "":
// 		return trace.BadParameter("missing parameter sessionID")
// 	}

// 	return trace.Wrap(s.Delete(ctx, sessionDataKey(user, sessionID)))
// }

func sessionDataKey(user, sessionID string) []byte {
	return backend.Key(webPrefix, usersPrefix, user, webauthnSessionData, sessionID)
}

// globalSessionDataLimiter keeps a count of in-flight session data challenges
// over a period of time.
type globalSessionDataLimiter struct {
	// Clock is public so it may be overwritten by tests.
	Clock clockwork.Clock
	// ResetPeriod is public so it may be overwritten by tests.
	ResetPeriod time.Duration
	// mu guards the fields below it.
	mu         sync.Mutex
	scopeCount map[string]int
	lastReset  time.Time
}

func (l *globalSessionDataLimiter) add(scope string, n int) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Reset counters to account for key expiration.
	now := l.Clock.Now()
	if now.Sub(l.lastReset) >= l.ResetPeriod {
		for k := range l.scopeCount {
			l.scopeCount[k] = 0
		}
		l.lastReset = now
	}

	v := l.scopeCount[scope] + n
	if v < 0 {
		v = 0
	}
	l.scopeCount[scope] = v
	return v
}

var sdLimiter = &globalSessionDataLimiter{
	Clock: clockwork.NewRealClock(),
	// Make ResetPeriod larger than the challenge expiration, so we are a bit
	// more conservative than storage.
	ResetPeriod: defaults.WebauthnGlobalChallengeTimeout + 10*time.Second,
	scopeCount:  make(map[string]int),
}

func (s *IdentityService) UpsertGlobalWebauthnSessionData(ctx context.Context, scope, id string, sd *wantypes.SessionData) error {
	switch {
	case scope == "":
		return trace.BadParameter("missing parameter scope")
	case id == "":
		return trace.BadParameter("missing parameter id")
	case sd == nil:
		return trace.BadParameter("missing parameter sd")
	}

	// Marshal before checking limiter, in case this fails.
	value, err := json.Marshal(sd)
	if err != nil {
		return trace.Wrap(err)
	}

	// Are we within the limits for the current time window?
	if entries := sdLimiter.add(scope, 1); entries > GlobalSessionDataMaxEntries {
		sdLimiter.add(scope, -1) // Request denied, adjust accordingly
		return trace.LimitExceeded("too many in-flight challenges")
	}

	if _, err = s.Put(ctx, backend.Item{
		Key:     globalSessionDataKey(scope, id),
		Value:   value,
		Expires: s.Clock().Now().UTC().Add(defaults.WebauthnGlobalChallengeTimeout),
	}); err != nil {
		sdLimiter.add(scope, -1) // Don't count eventual write failures
		return trace.Wrap(err)
	}
	return nil
}

func (s *IdentityService) GetGlobalWebauthnSessionData(ctx context.Context, scope, id string) (*wantypes.SessionData, error) {
	switch {
	case scope == "":
		return nil, trace.BadParameter("missing parameter scope")
	case id == "":
		return nil, trace.BadParameter("missing parameter id")
	}

	item, err := s.Get(ctx, globalSessionDataKey(scope, id))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sd := &wantypes.SessionData{}
	return sd, trace.Wrap(json.Unmarshal(item.Value, sd))
}

func (s *IdentityService) DeleteGlobalWebauthnSessionData(ctx context.Context, scope, id string) error {
	switch {
	case scope == "":
		return trace.BadParameter("missing parameter scope")
	case id == "":
		return trace.BadParameter("missing parameter id")
	}

	if err := s.Delete(ctx, globalSessionDataKey(scope, id)); err != nil {
		return trace.Wrap(err)
	}

	sdLimiter.add(scope, -1)
	return nil
}

func globalSessionDataKey(scope, id string) []byte {
	return backend.Key(webauthnPrefix, webauthnGlobalSessionData, scope, id)
}

func (s *IdentityService) UpsertMFADevice(ctx context.Context, user string, d *types.MFADevice) error {
	if user == "" {
		return trace.BadParameter("missing parameter user")
	}
	if err := d.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	devs, err := s.GetMFADevices(ctx, user, false)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, dd := range devs {
		switch {
		case d.Metadata.Name == dd.Metadata.Name && d.Id == dd.Id:
			// OK. Same Name and ID means we are doing an update.
			continue
		case d.Metadata.Name == dd.Metadata.Name && d.Id != dd.Id:
			// NOK. Same Name but different ID means it's a duplicate device.
			return trace.AlreadyExists("MFA device with name %q already exists", d.Metadata.Name)
		}

		// Disallow duplicate credential IDs if the new device is Webauthn.
		if d.GetWebauthn() == nil {
			continue
		}
		id1, ok := getCredentialID(d)
		if !ok {
			continue
		}
		id2, ok := getCredentialID(dd)
		if !ok {
			continue
		}
		if bytes.Equal(id1, id2) {
			return trace.AlreadyExists("credential ID already in use by device %q", dd.Metadata.Name)
		}
	}

	value, err := json.Marshal(d)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{
		Key:   backend.Key(webPrefix, usersPrefix, user, mfaDevicePrefix, d.Id),
		Value: value,
	}

	if _, err := s.Put(ctx, item); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func getCredentialID(d *types.MFADevice) ([]byte, bool) {
	switch d := d.Device.(type) {
	case *types.MFADevice_U2F:
		return d.U2F.KeyHandle, true
	case *types.MFADevice_Webauthn:
		return d.Webauthn.CredentialId, true
	}
	return nil, false
}

func (s *IdentityService) DeleteMFADevice(ctx context.Context, user, id string) error {
	if user == "" {
		return trace.BadParameter("missing parameter user")
	}
	if id == "" {
		return trace.BadParameter("missing parameter id")
	}

	err := s.Delete(ctx, backend.Key(webPrefix, usersPrefix, user, mfaDevicePrefix, id))
	return trace.Wrap(err)
}

func (s *IdentityService) GetMFADevices(ctx context.Context, user string, withSecrets bool) ([]*types.MFADevice, error) {
	if user == "" {
		return nil, trace.BadParameter("missing parameter user")
	}

	startKey := backend.Key(webPrefix, usersPrefix, user, mfaDevicePrefix)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	devices := make([]*types.MFADevice, 0, len(result.Items))
	for _, item := range result.Items {
		var d types.MFADevice
		if err := json.Unmarshal(item.Value, &d); err != nil {
			return nil, trace.Wrap(err)
		}
		if !withSecrets {
			devWithoutSensitiveData, err := d.WithoutSensitiveData()
			if err != nil {
				return nil, trace.Wrap(err)
			}
			d = *devWithoutSensitiveData
		}
		devices = append(devices, &d)
	}
	return devices, nil
}

// UpsertOIDCConnector upserts OIDC Connector
func (s *IdentityService) UpsertOIDCConnector(ctx context.Context, connector types.OIDCConnector) error {
	value, err := services.MarshalOIDCConnector(connector)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{
		Key:     backend.Key(webPrefix, connectorsPrefix, oidcPrefix, connectorsPrefix, connector.GetName()),
		Value:   value,
		Expires: connector.Expiry(),
		ID:      connector.GetResourceID(),
	}
	_, err = s.Put(ctx, item)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// DeleteOIDCConnector deletes OIDC Connector by name
func (s *IdentityService) DeleteOIDCConnector(ctx context.Context, name string) error {
	if name == "" {
		return trace.BadParameter("missing parameter name")
	}
	err := s.Delete(ctx, backend.Key(webPrefix, connectorsPrefix, oidcPrefix, connectorsPrefix, name))
	return trace.Wrap(err)
}

// GetOIDCConnector returns OIDC connector data, parameter 'withSecrets'
// includes or excludes client secret from return results
func (s *IdentityService) GetOIDCConnector(ctx context.Context, name string, withSecrets bool) (types.OIDCConnector, error) {
	if name == "" {
		return nil, trace.BadParameter("missing parameter name")
	}
	item, err := s.Get(ctx, backend.Key(webPrefix, connectorsPrefix, oidcPrefix, connectorsPrefix, name))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("OpenID connector '%v' is not configured", name)
		}
		return nil, trace.Wrap(err)
	}
	conn, err := services.UnmarshalOIDCConnector(item.Value,
		services.WithExpires(item.Expires))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !withSecrets {
		conn.SetClientSecret("")
		conn.SetGoogleServiceAccount("")
	}
	return conn, nil
}

// GetOIDCConnectors returns registered connectors, withSecrets adds or removes client secret from return results
func (s *IdentityService) GetOIDCConnectors(ctx context.Context, withSecrets bool) ([]types.OIDCConnector, error) {
	startKey := backend.Key(webPrefix, connectorsPrefix, oidcPrefix, connectorsPrefix)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connectors := make([]types.OIDCConnector, len(result.Items))
	for i, item := range result.Items {
		conn, err := services.UnmarshalOIDCConnector(
			item.Value, services.WithExpires(item.Expires))
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !withSecrets {
			conn.SetClientSecret("")
			conn.SetGoogleServiceAccount("")
		}
		connectors[i] = conn
	}
	return connectors, nil
}

// CreateOIDCAuthRequest creates new auth request
func (s *IdentityService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest, ttl time.Duration) error {
	if err := req.Check(); err != nil {
		return trace.Wrap(err)
	}
	value, err := json.Marshal(req)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{
		Key:     backend.Key(webPrefix, connectorsPrefix, oidcPrefix, requestsPrefix, req.StateToken),
		Value:   value,
		Expires: backend.Expiry(s.Clock(), ttl),
	}
	_, err = s.Create(ctx, item)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetOIDCAuthRequest returns OIDC auth request
func (s *IdentityService) GetOIDCAuthRequest(ctx context.Context, stateToken string) (*types.OIDCAuthRequest, error) {
	if stateToken == "" {
		return nil, trace.BadParameter("missing parameter stateToken")
	}
	item, err := s.Get(ctx, backend.Key(webPrefix, connectorsPrefix, oidcPrefix, requestsPrefix, stateToken))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var req types.OIDCAuthRequest
	if err := json.Unmarshal(item.Value, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

// CreateSSODiagnosticInfo creates new SAML diagnostic info record.
func (s *IdentityService) CreateSSODiagnosticInfo(ctx context.Context, authKind string, authRequestID string, entry types.SSODiagnosticInfo) error {
	if authRequestID == "" {
		return trace.BadParameter("missing parameter authRequestID")
	}

	switch authKind {
	case types.KindSAML, types.KindGithub, types.KindOIDC:
		// nothing to do
	default:
		return trace.BadParameter("unsupported authKind %q", authKind)
	}

	jsonValue, err := json.Marshal(entry)
	if err != nil {
		return trace.Wrap(err)
	}

	item := backend.Item{
		Key:     backend.Key(webPrefix, connectorsPrefix, authKind, requestsTracePrefix, authRequestID),
		Value:   jsonValue,
		Expires: backend.Expiry(s.Clock(), time.Minute*15),
	}
	_, err = s.Create(ctx, item)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetSSODiagnosticInfo returns SSO diagnostic info records.
func (s *IdentityService) GetSSODiagnosticInfo(ctx context.Context, authKind string, authRequestID string) (*types.SSODiagnosticInfo, error) {
	if authRequestID == "" {
		return nil, trace.BadParameter("missing parameter authRequestID")
	}

	switch authKind {
	case types.KindSAML, types.KindGithub, types.KindOIDC:
		// nothing to do
	default:
		return nil, trace.BadParameter("unsupported authKind %q", authKind)
	}

	item, err := s.Get(ctx, backend.Key(webPrefix, connectorsPrefix, authKind, requestsTracePrefix, authRequestID))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var req types.SSODiagnosticInfo
	if err := json.Unmarshal(item.Value, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// GetRecoveryCodes returns user's recovery codes.
func (s *IdentityService) GetRecoveryCodes(ctx context.Context, user string, withSecrets bool) (*types.RecoveryCodesV1, error) {
	if user == "" {
		return nil, trace.BadParameter("missing parameter user")
	}

	item, err := s.Get(ctx, backend.Key(webPrefix, usersPrefix, user, recoveryCodesPrefix))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var rc types.RecoveryCodesV1
	if err := json.Unmarshal(item.Value, &rc); err != nil {
		return nil, trace.Wrap(err)
	}

	if !withSecrets {
		rc.Spec.Codes = nil
	}

	return &rc, nil
}

// UpsertRecoveryCodes creates or updates user's account recovery codes.
// Each recovery code are hashed before upsert.
func (s *IdentityService) UpsertRecoveryCodes(ctx context.Context, user string, recovery *types.RecoveryCodesV1) error {
	if user == "" {
		return trace.BadParameter("missing parameter user")
	}

	if err := recovery.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	value, err := json.Marshal(recovery)
	if err != nil {
		return trace.Wrap(err)
	}

	item := backend.Item{
		Key:   backend.Key(webPrefix, usersPrefix, user, recoveryCodesPrefix),
		Value: value,
	}

	_, err = s.Put(ctx, item)
	return trace.Wrap(err)
}

// CreateUserRecoveryAttempt creates new user recovery attempt.
func (s *IdentityService) CreateUserRecoveryAttempt(ctx context.Context, user string, attempt *types.RecoveryAttempt) error {
	if user == "" {
		return trace.BadParameter("missing parameter user")
	}

	if err := attempt.Check(); err != nil {
		return trace.Wrap(err)
	}

	value, err := json.Marshal(attempt)
	if err != nil {
		return trace.Wrap(err)
	}

	item := backend.Item{
		Key:     backend.Key(webPrefix, usersPrefix, user, recoveryAttemptsPrefix, uuid.New().String()),
		Value:   value,
		Expires: attempt.Expires,
	}

	_, err = s.Create(ctx, item)
	return trace.Wrap(err)
}

// GetUserRecoveryAttempts returns users recovery attempts.
func (s *IdentityService) GetUserRecoveryAttempts(ctx context.Context, user string) ([]*types.RecoveryAttempt, error) {
	if user == "" {
		return nil, trace.BadParameter("missing parameter user")
	}

	startKey := backend.Key(webPrefix, usersPrefix, user, recoveryAttemptsPrefix)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	out := make([]*types.RecoveryAttempt, len(result.Items))
	for i, item := range result.Items {
		var a types.RecoveryAttempt
		if err := json.Unmarshal(item.Value, &a); err != nil {
			return nil, trace.Wrap(err)
		}
		out[i] = &a
	}

	sort.Sort(recoveryAttemptsChronologically(out))

	return out, nil
}

// DeleteUserRecoveryAttempts removes all recovery attempts of a user.
func (s *IdentityService) DeleteUserRecoveryAttempts(ctx context.Context, user string) error {
	if user == "" {
		return trace.BadParameter("missing parameter user")
	}

	startKey := backend.Key(webPrefix, usersPrefix, user, recoveryAttemptsPrefix)
	return trace.Wrap(s.DeleteRange(ctx, startKey, backend.RangeEnd(startKey)))
}

// recoveryAttemptsChronologically sorts recovery attempts by oldest to latest time.
type recoveryAttemptsChronologically []*types.RecoveryAttempt

func (s recoveryAttemptsChronologically) Len() int {
	return len(s)
}

// Less stacks latest attempts to the end of the list.
func (s recoveryAttemptsChronologically) Less(i, j int) bool {
	return s[i].Time.Before(s[j].Time)
}

func (s recoveryAttemptsChronologically) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

const (
	webPrefix        = "web"
	usersPrefix      = "users"
	sessionsPrefix   = "sessions"
	attemptsPrefix   = "attempts"
	pwdPrefix        = "pwd"
	hotpPrefix       = "hotp"
	connectorsPrefix = "connectors"
	oidcPrefix       = "oidc"
	// samlPrefix                = "saml"
	// githubPrefix              = "github"
	requestsPrefix            = "requests"
	requestsTracePrefix       = "requestsTrace"
	usedTOTPPrefix            = "used_totp"
	usedTOTPTTL               = 30 * time.Second
	mfaDevicePrefix           = "mfa"
	webauthnPrefix            = "webauthn"
	webauthnGlobalSessionData = "sessionData"
	webauthnLocalAuthPrefix   = "webauthnlocalauth"
	webauthnSessionData       = "webauthnsessiondata"
	recoveryCodesPrefix       = "recoverycodes"
	recoveryAttemptsPrefix    = "recoveryattempts"
)
