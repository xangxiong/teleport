/*
Copyright 2015-2021 Gravitational, Inc.

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
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	collectortracev1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	otlpcommonv1 "go.opentelemetry.io/proto/otlp/common/v1"
)

// ServerWithRoles is a wrapper around auth service
// methods that focuses on authorizing every request
type ServerWithRoles struct {
	authServer *Server
	sessions   session.Service
	alog       events.IAuditLog
	// context holds authorization context
	context Context
}

// CloseContext is closed when the auth server shuts down
func (a *ServerWithRoles) CloseContext() context.Context {
	return a.authServer.closeCtx
}

func (a *ServerWithRoles) actionWithContext(ctx *services.Context, namespace, resource string, verbs ...string) error {
	if len(verbs) == 0 {
		return trace.BadParameter("no verbs provided for authorization check on resource %q", resource)
	}
	var errs []error
	for _, verb := range verbs {
		errs = append(errs, a.context.Checker.CheckAccessToRule(ctx, namespace, resource, verb, false))
	}
	// Convert generic aggregate error to AccessDenied.
	if err := trace.NewAggregate(errs...); err != nil {
		return trace.AccessDenied(err.Error())
	}
	return nil
}

type actionConfig struct {
	quiet   bool
	context Context
}

type actionOption func(*actionConfig)

func quietAction(quiet bool) actionOption {
	return func(cfg *actionConfig) {
		cfg.quiet = quiet
	}
}

func (a *ServerWithRoles) withOptions(opts ...actionOption) actionConfig {
	cfg := actionConfig{context: a.context}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

func (c actionConfig) action(namespace, resource string, verbs ...string) error {
	if len(verbs) == 0 {
		return trace.BadParameter("no verbs provided for authorization check on resource %q", resource)
	}
	var errs []error
	for _, verb := range verbs {
		errs = append(errs, c.context.Checker.CheckAccessToRule(&services.Context{User: c.context.User}, namespace, resource, verb, c.quiet))
	}
	// Convert generic aggregate error to AccessDenied.
	if err := trace.NewAggregate(errs...); err != nil {
		return trace.AccessDenied(err.Error())
	}
	return nil
}

func (a *ServerWithRoles) action(namespace, resource string, verbs ...string) error {
	return a.withOptions().action(namespace, resource, verbs...)
}

// currentUserAction is a special checker that allows certain actions for users
// even if they are not admins, e.g. update their own passwords,
// or generate certificates, otherwise it will require admin privileges
func (a *ServerWithRoles) currentUserAction(username string) error {
	if hasLocalUserRole(a.context) && username == a.context.User.GetName() {
		return nil
	}
	return a.context.Checker.CheckAccessToRule(&services.Context{User: a.context.User},
		apidefaults.Namespace, types.KindUser, types.VerbCreate, true)
}

// actionForListWithCondition extracts a restrictive filter condition to be
// added to a list query after a simple resource check fails.
func (a *ServerWithRoles) actionForListWithCondition(namespace, resource, identifier string) (*types.WhereExpr, error) {
	origErr := a.withOptions(quietAction(true)).action(namespace, resource, types.VerbList)
	if origErr == nil || !trace.IsAccessDenied(origErr) {
		return nil, trace.Wrap(origErr)
	}
	cond, err := a.context.Checker.ExtractConditionForIdentifier(&services.Context{User: a.context.User}, namespace, resource, types.VerbList, identifier)
	if trace.IsAccessDenied(err) {
		log.WithError(err).Infof("Access to %v %v in namespace %v denied to %v.", types.VerbList, resource, namespace, a.context.Checker)
		// Return the original AccessDenied to avoid leaking information.
		return nil, trace.Wrap(origErr)
	}
	return cond, trace.Wrap(err)
}

// actionWithExtendedContext performs an additional RBAC check with extended
// rule context after a simple resource check fails.
func (a *ServerWithRoles) actionWithExtendedContext(namespace, kind, verb string, extendContext func(*services.Context) error) error {
	ruleCtx := &services.Context{User: a.context.User}
	origErr := a.context.Checker.CheckAccessToRule(ruleCtx, namespace, kind, verb, true)
	if origErr == nil || !trace.IsAccessDenied(origErr) {
		return trace.Wrap(origErr)
	}
	if err := extendContext(ruleCtx); err != nil {
		log.WithError(err).Warning("Failed to extend context for second RBAC check.")
		// Return the original AccessDenied to avoid leaking information.
		return trace.Wrap(origErr)
	}
	return trace.Wrap(a.context.Checker.CheckAccessToRule(ruleCtx, namespace, kind, verb, false))
}

// actionForKindSession is a special checker that grants access to session
// recordings.  It can allow access to a specific recording based on the
// `where` section of the user's access rule for kind `session`.
func (a *ServerWithRoles) actionForKindSession(namespace, verb string, sid session.ID) error {
	extendContext := func(ctx *services.Context) error {
		sessionEnd, err := a.findSessionEndEvent(namespace, sid)
		ctx.Session = sessionEnd
		return trace.Wrap(err)
	}
	return trace.Wrap(a.actionWithExtendedContext(namespace, types.KindSession, verb, extendContext))
}

// actionForKindSSHSession is a special checker that grants access to active SSH
// sessions.  It can allow access to a specific session based on the `where`
// section of the user's access rule for kind `ssh_session`.
func (a *ServerWithRoles) actionForKindSSHSession(ctx context.Context, namespace, verb string, sid session.ID) error {
	extendContext := func(serviceContext *services.Context) error {
		session, err := a.sessions.GetSession(ctx, namespace, sid)
		serviceContext.SSHSession = session
		return trace.Wrap(err)
	}
	return trace.Wrap(a.actionWithExtendedContext(namespace, types.KindSSHSession, verb, extendContext))
}

// serverAction returns an access denied error if the role is not one of the builtin server roles.
func (a *ServerWithRoles) serverAction() error {
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return trace.AccessDenied("this request can be only executed by a teleport built-in server")
	}
	return nil
}

// hasBuiltinRole checks that the attached identity is a builtin role and
// whether any of the given roles match the role set.
func (a *ServerWithRoles) hasBuiltinRole(roles ...types.SystemRole) bool {
	for _, role := range roles {
		if HasBuiltinRole(a.context, string(role)) {
			return true
		}
	}
	return false
}

// HasBuiltinRole checks if the identity is a builtin role with the matching
// name.
func HasBuiltinRole(authContext Context, name string) bool {
	if _, ok := authContext.Identity.(BuiltinRole); !ok {
		return false
	}
	if !authContext.Checker.HasRole(name) {
		return false
	}

	return true
}

// HasRemoteBuiltinRole checks if the identity is a remote builtin role with the
// matching name.
func HasRemoteBuiltinRole(authContext Context, name string) bool {
	if _, ok := authContext.UnmappedIdentity.(RemoteBuiltinRole); !ok {
		return false
	}
	if !authContext.Checker.HasRole(name) {
		return false
	}
	return true
}

// hasRemoteBuiltinRole checks if the identity is a remote builtin role and the
// name matches.
func (a *ServerWithRoles) hasRemoteBuiltinRole(name string) bool {
	return HasRemoteBuiltinRole(a.context, name)
}

// hasLocalUserRole checks if the identity is a local user or not.
func hasLocalUserRole(authContext Context) bool {
	_, ok := authContext.UnmappedIdentity.(LocalUser)
	return ok
}

// CreateSessionTracker creates a tracker resource for an active session.
func (a *ServerWithRoles) CreateSessionTracker(ctx context.Context, tracker types.SessionTracker) (types.SessionTracker, error) {
	if err := a.serverAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	tracker, err := a.authServer.CreateSessionTracker(ctx, tracker)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return tracker, nil
}

func (a *ServerWithRoles) filterSessionTracker(ctx context.Context, joinerRoles []types.Role, tracker types.SessionTracker) bool {
	evaluator := NewSessionAccessEvaluator(tracker.GetHostPolicySets(), tracker.GetSessionKind(), tracker.GetHostUser())
	modes := evaluator.CanJoin(SessionAccessContext{Username: a.context.User.GetName(), Roles: joinerRoles})

	if len(modes) == 0 {
		return false
	}

	// Apply RFD 45 RBAC rules to the session if it's SSH.
	// This is a bit of a hack. It converts to the old legacy format
	// which we don't have all data for, luckily the fields we don't have aren't made available
	// to the RBAC filter anyway.
	if tracker.GetKind() == types.KindSSHSession {
		ruleCtx := &services.Context{User: a.context.User}
		ruleCtx.SSHSession = &session.Session{
			ID:             session.ID(tracker.GetSessionID()),
			Namespace:      apidefaults.Namespace,
			Login:          tracker.GetLogin(),
			Created:        tracker.GetCreated(),
			LastActive:     a.authServer.GetClock().Now(),
			ServerID:       tracker.GetAddress(),
			ServerAddr:     tracker.GetAddress(),
			ServerHostname: tracker.GetHostname(),
			ClusterName:    tracker.GetClusterName(),
		}

		for _, participant := range tracker.GetParticipants() {
			// We only need to fill in User here since other fields get discarded anyway.
			ruleCtx.SSHSession.Parties = append(ruleCtx.SSHSession.Parties, session.Party{
				User: participant.User,
			})
		}

		// Skip past it if there's a deny rule in place blocking access.
		if err := a.context.Checker.CheckAccessToRule(ruleCtx, apidefaults.Namespace, types.KindSSHSession, types.VerbList, true /* silent */); err != nil {
			return false
		}
	}

	return true
}

const (
	forwardedTag = "teleport.forwarded.for"
)

// Export forwards OTLP traces to the upstream collector configured in the tracing service. This allows for
// tsh, tctl, etc to be able to export traces without having to know how to connect to the upstream collector
// for the cluster.
//
// All spans received will have a `teleport.forwarded.for` attribute added to them with the value being one of
// two things depending on the role of the forwarder:
//  1. User forwarded: `teleport.forwarded.for: alice`
//  2. Instance forwarded: `teleport.forwarded.for: Proxy.clustername:Proxy,Node,Instance`
//
// This allows upstream consumers of the spans to be able to identify forwarded spans and act on them accordingly.
func (a *ServerWithRoles) Export(ctx context.Context, req *collectortracev1.ExportTraceServiceRequest) (*collectortracev1.ExportTraceServiceResponse, error) {
	var sb strings.Builder

	sb.WriteString(a.context.User.GetName())

	// if forwarded on behalf of a Teleport service add its system roles
	if role, ok := a.context.Identity.(BuiltinRole); ok {
		sb.WriteRune(':')
		sb.WriteString(role.Role.String())
		if len(role.AdditionalSystemRoles) > 0 {
			sb.WriteRune(',')
			sb.WriteString(role.AdditionalSystemRoles.String())
		}
	}

	// the forwarded attribute to add
	value := &otlpcommonv1.KeyValue{
		Key: forwardedTag,
		Value: &otlpcommonv1.AnyValue{
			Value: &otlpcommonv1.AnyValue_StringValue{
				StringValue: sb.String(),
			},
		},
	}

	// returns the index at which the attribute with
	// the forwardedTag key exists, -1 if not found
	tagIndex := func(attrs []*otlpcommonv1.KeyValue) int {
		for i, attr := range attrs {
			if attr.Key == forwardedTag {
				return i
			}
		}

		return -1
	}

	for _, resourceSpans := range req.ResourceSpans {
		// if there is a resource, tag it with the
		// forwarded attribute instead of each of tagging
		// each span
		if resourceSpans.Resource != nil {
			if index := tagIndex(resourceSpans.Resource.Attributes); index != -1 {
				resourceSpans.Resource.Attributes[index] = value
			} else {
				resourceSpans.Resource.Attributes = append(resourceSpans.Resource.Attributes, value)
			}

			// override any span attributes with a forwarded tag,
			// but we don't need to add one if the span isn't already
			// tagged since we just tagged the resource
			for _, scopeSpans := range resourceSpans.ScopeSpans {
				for _, span := range scopeSpans.Spans {
					if index := tagIndex(span.Attributes); index != -1 {
						span.Attributes[index] = value
					}
				}
			}

			continue
		}

		// there was no resource, so we must now tag all the
		// individual spans with the forwarded tag
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			for _, span := range scopeSpans.Spans {
				if index := tagIndex(span.Attributes); index != -1 {
					span.Attributes[index] = value
				} else {
					span.Attributes = append(span.Attributes, value)
				}
			}
		}
	}

	if err := a.authServer.traceClient.UploadTraces(ctx, req.ResourceSpans); err != nil {
		return &collectortracev1.ExportTraceServiceResponse{}, trace.Wrap(err)
	}

	return &collectortracev1.ExportTraceServiceResponse{}, nil
}

// GetSessionTracker returns the current state of a session tracker for an active session.
func (a *ServerWithRoles) GetSessionTracker(ctx context.Context, sessionID string) (types.SessionTracker, error) {
	tracker, err := a.authServer.GetSessionTracker(ctx, sessionID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.serverAction(); err == nil {
		return tracker, nil
	}

	user := a.context.User
	joinerRoles, err := services.FetchRoles(user.GetRoles(), a.authServer, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ok := a.filterSessionTracker(ctx, joinerRoles, tracker)
	if !ok {
		return nil, trace.NotFound("session %v not found", sessionID)
	}

	return tracker, nil
}

// GetActiveSessionTrackers returns a list of active session trackers.
func (a *ServerWithRoles) GetActiveSessionTrackers(ctx context.Context) ([]types.SessionTracker, error) {
	sessions, err := a.authServer.GetActiveSessionTrackers(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.serverAction(); err == nil {
		return sessions, nil
	}

	var filteredSessions []types.SessionTracker
	user := a.context.User
	joinerRoles, err := services.FetchRoles(user.GetRoles(), a.authServer, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, sess := range sessions {
		ok := a.filterSessionTracker(ctx, joinerRoles, sess)
		if ok {
			filteredSessions = append(filteredSessions, sess)
		}
	}

	return filteredSessions, nil
}

// RemoveSessionTracker removes a tracker resource for an active session.
func (a *ServerWithRoles) RemoveSessionTracker(ctx context.Context, sessionID string) error {
	if err := a.serverAction(); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.RemoveSessionTracker(ctx, sessionID)
}

// UpdateSessionTracker updates a tracker resource for an active session.
func (a *ServerWithRoles) UpdateSessionTracker(ctx context.Context, req *proto.UpdateSessionTrackerRequest) error {
	if err := a.serverAction(); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.UpdateSessionTracker(ctx, req)
}

func (a *ServerWithRoles) GetSession(ctx context.Context, namespace string, id session.ID) (*session.Session, error) {
	if err := a.actionForKindSSHSession(ctx, namespace, types.VerbRead, id); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.sessions.GetSession(ctx, namespace, id)
}

func (a *ServerWithRoles) CreateSession(ctx context.Context, s session.Session) error {
	if err := a.action(s.Namespace, types.KindSSHSession, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.CreateSession(ctx, s)
}

func (a *ServerWithRoles) UpdateSession(ctx context.Context, req session.UpdateRequest) error {
	if err := a.actionForKindSSHSession(ctx, req.Namespace, types.VerbUpdate, req.ID); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.UpdateSession(ctx, req)
}

// DeleteSession removes an active session from the backend.
func (a *ServerWithRoles) DeleteSession(ctx context.Context, namespace string, id session.ID) error {
	if err := a.actionForKindSSHSession(ctx, namespace, types.VerbDelete, id); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.DeleteSession(ctx, namespace, id)
}

// CreateCertAuthority not implemented: can only be called locally.
func (a *ServerWithRoles) CreateCertAuthority(ca types.CertAuthority) error {
	return trace.NotImplemented(notImplementedMessage)
}

// RotateCertAuthority starts or restarts certificate authority rotation process.
func (a *ServerWithRoles) RotateCertAuthority(ctx context.Context, req RotateRequest) error {
	if err := req.CheckAndSetDefaults(a.authServer.clock); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.RotateCertAuthority(ctx, req)
}

// RotateExternalCertAuthority rotates external certificate authority,
// this method is called by a remote trusted cluster and is used to update
// only public keys and certificates of the certificate authority.
func (a *ServerWithRoles) RotateExternalCertAuthority(ctx context.Context, ca types.CertAuthority) error {
	if ca == nil {
		return trace.BadParameter("missing certificate authority")
	}
	sctx := &services.Context{User: a.context.User, Resource: ca}
	if err := a.actionWithContext(sctx, apidefaults.Namespace, types.KindCertAuthority, types.VerbRotate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.RotateExternalCertAuthority(ctx, ca)
}

// UpsertCertAuthority updates existing cert authority or updates the existing one.
func (a *ServerWithRoles) UpsertCertAuthority(ca types.CertAuthority) error {
	if ca == nil {
		return trace.BadParameter("missing certificate authority")
	}
	ctx := &services.Context{User: a.context.User, Resource: ca}
	if err := a.actionWithContext(ctx, apidefaults.Namespace, types.KindCertAuthority, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertCertAuthority(ca)
}

// CompareAndSwapCertAuthority updates existing cert authority if the existing cert authority
// value matches the value stored in the backend.
func (a *ServerWithRoles) CompareAndSwapCertAuthority(new, existing types.CertAuthority) error {
	if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CompareAndSwapCertAuthority(new, existing)
}

func (a *ServerWithRoles) GetCertAuthorities(ctx context.Context, caType types.CertAuthType, loadKeys bool, opts ...services.MarshalOption) ([]types.CertAuthority, error) {
	if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbList, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if loadKeys {
		if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetCertAuthorities(ctx, caType, loadKeys, opts...)
}

func (a *ServerWithRoles) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool, opts ...services.MarshalOption) (types.CertAuthority, error) {
	if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if loadKeys {
		if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetCertAuthority(ctx, id, loadKeys, opts...)
}

func (a *ServerWithRoles) GetDomainName(ctx context.Context) (string, error) {
	// anyone can read it, no harm in that
	return a.authServer.GetDomainName()
}

// getClusterCACert returns the PEM-encoded TLS certs for the local cluster
// without signing keys. If the cluster has multiple TLS certs, they will all
// be concatenated.
func (a *ServerWithRoles) GetClusterCACert(
	ctx context.Context,
) (*proto.GetClusterCACertResponse, error) {
	// Allow all roles to get the CA certs.
	return a.authServer.GetClusterCACert(ctx)
}

func (a *ServerWithRoles) DeleteCertAuthority(id types.CertAuthID) error {
	if err := a.action(apidefaults.Namespace, types.KindCertAuthority, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteCertAuthority(id)
}

// ActivateCertAuthority not implemented: can only be called locally.
func (a *ServerWithRoles) ActivateCertAuthority(id types.CertAuthID) error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeactivateCertAuthority not implemented: can only be called locally.
func (a *ServerWithRoles) DeactivateCertAuthority(id types.CertAuthID) error {
	return trace.NotImplemented(notImplementedMessage)
}

// GenerateToken generates multi-purpose authentication token.
func (a *ServerWithRoles) GenerateToken(ctx context.Context, req *proto.GenerateTokenRequest) (string, error) {
	if err := a.action(apidefaults.Namespace, types.KindToken, types.VerbCreate); err != nil {
		return "", trace.Wrap(err)
	}
	return a.authServer.GenerateToken(ctx, req)
}

func (a *ServerWithRoles) RegisterUsingToken(ctx context.Context, req *types.RegisterUsingTokenRequest) (*proto.Certs, error) {
	// tokens have authz mechanism  on their own, no need to check
	return a.authServer.RegisterUsingToken(ctx, req)
}

func (a *ServerWithRoles) RegisterNewAuthServer(ctx context.Context, token string) error {
	// tokens have authz mechanism  on their own, no need to check
	return a.authServer.RegisterNewAuthServer(ctx, token)
}

// RegisterUsingIAMMethod registers the caller using the IAM join method and
// returns signed certs to join the cluster.
//
// See (*Server).RegisterUsingIAMMethod for further documentation.
//
// This wrapper does not do any extra authz checks, as the register method has
// its own authz mechanism.
func (a *ServerWithRoles) RegisterUsingIAMMethod(ctx context.Context, challengeResponse client.RegisterChallengeResponseFunc) (*proto.Certs, error) {
	return nil, nil
}

// GenerateHostCerts generates new host certificates (signed
// by the host certificate authority) for a node.
func (a *ServerWithRoles) GenerateHostCerts(ctx context.Context, req *proto.HostCertsRequest) (*proto.Certs, error) {
	clusterName, err := a.authServer.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// username is hostID + cluster name, so make sure server requests new keys for itself
	if a.context.User.GetName() != HostFQDN(req.HostID, clusterName) {
		return nil, trace.AccessDenied("username mismatch %q and %q", a.context.User.GetName(), HostFQDN(req.HostID, clusterName))
	}

	if req.Role == types.RoleInstance {
		if err := a.checkAdditionalSystemRoles(ctx, req); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if len(req.SystemRoles) != 0 {
			return nil, trace.AccessDenied("additional system role encoding not supported for certs of type %q", req.Role)
		}
	}

	existingRoles, err := types.NewTeleportRoles(a.context.User.GetRoles())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// prohibit privilege escalations through role changes (except the instance cert exception, handled above).
	if !a.hasBuiltinRole(req.Role) && req.Role != types.RoleInstance {
		return nil, trace.AccessDenied("roles do not match: %v and %v", existingRoles, req.Role)
	}
	return a.authServer.GenerateHostCerts(ctx, req)
}

// checkAdditionalSystemRoles verifies additional system roles in host cert request.
func (a *ServerWithRoles) checkAdditionalSystemRoles(ctx context.Context, req *proto.HostCertsRequest) error {
	// ensure requesting cert's primary role is a server role.
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return trace.AccessDenied("additional system roles can only be claimed by a teleport built-in server")
	}

	// check that additional system roles are theoretically valid (distinct from permissibility, which
	// is checked in the following loop).
	for _, r := range req.SystemRoles {
		if r.Check() != nil {
			return trace.AccessDenied("additional system role %q cannot be applied (not a valid system role)", r)
		}
		if !r.IsLocalService() {
			return trace.AccessDenied("additional system role %q cannot be applied (not a builtin service role)", r)
		}
	}

	// load system role assertions if relevant
	var assertions proto.UnstableSystemRoleAssertionSet
	var err error
	if req.UnstableSystemRoleAssertionID != "" {
		assertions, err = a.authServer.UnstableGetSystemRoleAssertions(ctx, req.HostID, req.UnstableSystemRoleAssertionID)
		if err != nil {
			// include this error in the logs, since it might be indicative of a bug if it occurs outside of the context
			// of a general backend outage.
			log.Warnf("Failed to load system role assertion set %q for instance %q: %v", req.UnstableSystemRoleAssertionID, req.HostID, err)
			return trace.AccessDenied("failed to load system role assertion set with ID %q", req.UnstableSystemRoleAssertionID)
		}
	}

	// check if additional system roles are permissible
Outer:
	for _, requestedRole := range req.SystemRoles {
		if a.hasBuiltinRole(requestedRole) {
			// instance is already known to hold this role
			continue Outer
		}

		for _, assertedRole := range assertions.SystemRoles {
			if requestedRole == assertedRole {
				// instance recently demonstrated that it holds this role
				continue Outer
			}
		}

		return trace.AccessDenied("additional system role %q cannot be applied (not authorized)", requestedRole)
	}

	return nil
}

func (a *ServerWithRoles) UnstableAssertSystemRole(ctx context.Context, req proto.UnstableSystemRoleAssertion) error {
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return trace.AccessDenied("system role assertions can only be executed by a teleport built-in server")
	}

	if req.ServerID != role.GetServerID() {
		return trace.AccessDenied("system role assertions do not support impersonation (%q -> %q)", role.GetServerID(), req.ServerID)
	}

	if !a.hasBuiltinRole(req.SystemRole) {
		return trace.AccessDenied("cannot assert unheld system role %q", req.SystemRole)
	}

	if !req.SystemRole.IsLocalService() {
		return trace.AccessDenied("cannot assert non-service system role %q", req.SystemRole)
	}

	return a.authServer.UnstableAssertSystemRole(ctx, req)
}

func (a *ServerWithRoles) RegisterInventoryControlStream(ics client.UpstreamInventoryControlStream) error {
	// Ensure that caller is a teleport server
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return trace.AccessDenied("inventory control streams can only be created by a teleport built-in server")
	}

	// wait for upstream hello
	var upstreamHello proto.UpstreamInventoryHello
	select {
	case msg := <-ics.Recv():
		switch m := msg.(type) {
		case proto.UpstreamInventoryHello:
			upstreamHello = m
		default:
			return trace.BadParameter("expected upstream hello, got: %T", m)
		}
	case <-ics.Done():
		return trace.Wrap(ics.Error())
	case <-a.CloseContext().Done():
		return trace.Errorf("auth server shutdown")
	}

	// verify that server is creating stream on behalf of itself.
	if upstreamHello.ServerID != role.GetServerID() {
		return trace.AccessDenied("control streams do not support impersonation (%q -> %q)", role.GetServerID(), upstreamHello.ServerID)
	}

	// in order to reduce sensitivity to downgrades/misconfigurations, we simply filter out
	// services that are unrecognized or unauthorized, rather than rejecting hellos that claim them.
	var filteredServices []types.SystemRole
	for _, service := range upstreamHello.Services {
		if !a.hasBuiltinRole(service) {
			log.Warnf("Omitting service %q for control stream of instance %q (unknown or unauthorized).", service, role.GetServerID())
			continue
		}
		filteredServices = append(filteredServices, service)
	}

	upstreamHello.Services = filteredServices

	return a.authServer.RegisterInventoryControlStream(ics, upstreamHello)
}

func (a *ServerWithRoles) GetInventoryStatus(ctx context.Context, req proto.InventoryStatusRequest) (proto.InventoryStatusSummary, error) {
	// only support builtin roles for now, but we'll eventually want to develop an RBAC syntax for
	// the inventory APIs once they are more developed.
	return a.authServer.GetInventoryStatus(ctx, req), nil
}

func (a *ServerWithRoles) PingInventory(ctx context.Context, req proto.InventoryPingRequest) (proto.InventoryPingResponse, error) {
	// admin-only for now, but we'll eventually want to develop an RBAC syntax for
	// the inventory APIs once they are more developed.
	return a.authServer.PingInventory(ctx, req)
}

func (a *ServerWithRoles) GetClusterAlerts(ctx context.Context, query types.GetClusterAlertsRequest) ([]types.ClusterAlert, error) {
	// unauthenticated clients can never check for alerts. we don't normally explicitly
	// check for this kind of thing, but since alerts use an unusual access-control
	// pattern, explicitly rejecting the nop role makes things easier.
	if a.hasBuiltinRole(types.RoleNop) {
		return nil, trace.AccessDenied("alerts not available to unauthenticated clients")
	}

	alerts, err := a.authServer.GetClusterAlerts(ctx, query)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// filter alerts by teleport.internal labels to determine whether the alert
	// was intended to be visible to the calling user.
	filtered := alerts[:0]
	for _, alert := range alerts {
		if alert.Metadata.Labels[types.AlertPermitAll] == "yes" {
			// alert may be shown to all authenticated users
			filtered = append(filtered, alert)
			continue
		}

		// TODO(fspmarshall): Support additional internal labels to help customize alert targets.
		// maybe we could use labels to specify that an alert should only be shown to users with a
		// specific permission (e.g. `"teleport.internal/alert-permit-permission": "node:read"`).
		// requires further consideration.
	}

	return filtered, nil
}

func (a *ServerWithRoles) UpsertClusterAlert(ctx context.Context, alert types.ClusterAlert) error {
	// admin-only API. the expected usage of this is mostly as something the auth server itself would do
	// internally, but it is useful to be able to create alerts via tctl for testing/debug purposes.
	return a.authServer.UpsertClusterAlert(ctx, alert)
}

func (a *ServerWithRoles) UpsertNode(ctx context.Context, s types.Server) (*types.KeepAlive, error) {
	if err := a.action(s.GetNamespace(), types.KindNode, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.UpsertNode(ctx, s)
}

// DELETE IN: 5.1.0
//
// This logic has moved to KeepAliveServer.
func (a *ServerWithRoles) KeepAliveNode(ctx context.Context, handle types.KeepAlive) error {
	if !a.hasBuiltinRole(types.RoleNode) {
		return trace.AccessDenied("[10] access denied")
	}
	clusterName, err := a.GetDomainName(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	serverName, err := ExtractHostID(a.context.User.GetName(), clusterName)
	if err != nil {
		return trace.AccessDenied("[10] access denied")
	}
	if serverName != handle.Name {
		return trace.AccessDenied("[10] access denied")
	}
	if err := a.action(apidefaults.Namespace, types.KindNode, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.KeepAliveNode(ctx, handle)
}

// KeepAliveServer updates expiry time of a server resource.
func (a *ServerWithRoles) KeepAliveServer(ctx context.Context, handle types.KeepAlive) error {
	clusterName, err := a.GetDomainName(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	serverName, err := ExtractHostID(a.context.User.GetName(), clusterName)
	if err != nil {
		return trace.AccessDenied("access denied")
	}

	switch handle.GetType() {
	case constants.KeepAliveNode:
		if serverName != handle.Name {
			return trace.AccessDenied("access denied")
		}
		if !a.hasBuiltinRole(types.RoleNode) {
			return trace.AccessDenied("access denied")
		}
		if err := a.action(apidefaults.Namespace, types.KindNode, types.VerbUpdate); err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.BadParameter("unknown keep alive type %q", handle.Type)
	}

	return a.authServer.KeepAliveServer(ctx, handle)
}

// NewWatcher returns a new event watcher
func (a *ServerWithRoles) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	if len(watch.Kinds) == 0 {
		return nil, trace.AccessDenied("can't setup global watch")
	}
	for _, kind := range watch.Kinds {
		// Check the permissions for data of each kind. For watching, most
		// kinds of data just need a Read permission, but some have more
		// complicated logic.
		switch kind.Kind {
		case types.KindCertAuthority:
			verb := types.VerbReadNoSecrets
			if kind.LoadSecrets {
				verb = types.VerbRead
			}
			if err := a.action(apidefaults.Namespace, types.KindCertAuthority, verb); err != nil {
				return nil, trace.Wrap(err)
			}
		case types.KindAccessRequest:
			var filter types.AccessRequestFilter
			if err := filter.FromMap(kind.Filter); err != nil {
				return nil, trace.Wrap(err)
			}
			if filter.User == "" || a.currentUserAction(filter.User) != nil {
				if err := a.action(apidefaults.Namespace, types.KindAccessRequest, types.VerbRead); err != nil {
					return nil, trace.Wrap(err)
				}
			}
		case types.KindWebToken:
			if err := a.action(apidefaults.Namespace, types.KindWebToken, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		case types.KindRemoteCluster:
			if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		default:
			if err := a.action(apidefaults.Namespace, kind.Kind, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		}
	}
	switch {
	case a.hasBuiltinRole(types.RoleProxy):
		watch.QueueSize = defaults.ProxyQueueSize
	case a.hasBuiltinRole(types.RoleNode):
		watch.QueueSize = defaults.NodeQueueSize
	}
	return a.authServer.NewWatcher(ctx, watch)
}

// DeleteAllNodes deletes all nodes in a given namespace
func (a *ServerWithRoles) DeleteAllNodes(ctx context.Context, namespace string) error {
	if err := a.action(namespace, types.KindNode, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAllNodes(ctx, namespace)
}

// DeleteNode deletes node in the namespace
func (a *ServerWithRoles) DeleteNode(ctx context.Context, namespace, node string) error {
	if err := a.action(namespace, types.KindNode, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteNode(ctx, namespace, node)
}

// GetNode gets a node by name and namespace.
func (a *ServerWithRoles) GetNode(ctx context.Context, namespace, name string) (types.Server, error) {
	if err := a.action(namespace, types.KindNode, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	node, err := a.authServer.GetNode(ctx, namespace, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.checkAccessToNode(node); err != nil {
		if trace.IsAccessDenied(err) {
			return nil, trace.NotFound("not found")
		}

		return nil, trace.Wrap(err)
	}

	return node, nil
}

func (a *ServerWithRoles) GetNodes(ctx context.Context, namespace string) ([]types.Server, error) {
	if err := a.action(namespace, types.KindNode, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	// Fetch full list of nodes in the backend.
	startFetch := time.Now()
	nodes, err := a.authServer.GetNodes(ctx, namespace)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	elapsedFetch := time.Since(startFetch)

	// Filter nodes to return the ones for the connected identity.
	filteredNodes := make([]types.Server, 0)
	startFilter := time.Now()
	for _, node := range nodes {
		if err := a.checkAccessToNode(node); err != nil {
			if trace.IsAccessDenied(err) {
				continue
			}

			return nil, trace.Wrap(err)
		}

		filteredNodes = append(filteredNodes, node)
	}
	elapsedFilter := time.Since(startFilter)

	log.WithFields(logrus.Fields{
		"user":           a.context.User.GetName(),
		"elapsed_fetch":  elapsedFetch,
		"elapsed_filter": elapsedFilter,
	}).Debugf(
		"GetServers(%v->%v) in %v.",
		len(nodes), len(filteredNodes), elapsedFetch+elapsedFilter)

	return filteredNodes, nil
}

// ListResources returns a paginated list of resources filtered by user access.
func (a *ServerWithRoles) ListResources(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	if req.UseSearchAsRoles {
		clusterName, err := a.authServer.GetClusterName()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// For search-based access requests, replace the current roles with all
		// roles the user is allowed to search with.
		if err := a.context.UseSearchAsRoles(services.RoleGetter(a.authServer), clusterName.GetClusterName()); err != nil {
			return nil, trace.Wrap(err)
		}
		a.authServer.emitter.EmitAuditEvent(a.authServer.closeCtx, &apievents.AccessRequestResourceSearch{
			Metadata: apievents.Metadata{
				Type: events.AccessRequestResourceSearch,
				Code: events.AccessRequestResourceSearchCode,
			},
			UserMetadata:        ClientUserMetadata(ctx),
			SearchAsRoles:       a.context.Checker.RoleNames(),
			ResourceType:        req.ResourceType,
			Namespace:           req.Namespace,
			Labels:              req.Labels,
			PredicateExpression: req.PredicateExpression,
			SearchKeywords:      req.SearchKeywords,
		})
	}

	// ListResources request coming through this auth layer gets request filters
	// stripped off and saved to be applied later after items go through rbac checks.
	// The list that gets returned from the backend comes back unfiltered and as
	// we apply request filters, we might make multiple trips to get more subsets to
	// reach our limit, which is fine b/c we can start query with our next key.
	//
	// But since sorting and counting totals requires us to work with entire list upfront,
	// special handling is needed in this layer b/c if we try to mimic the "subset" here,
	// we will be making unnecessary trips and doing needless work of deserializing every
	// item for every subset.
	if req.RequiresFakePagination() {
		resp, err := a.listResourcesWithSort(ctx, req)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return resp, nil
	}

	// Start real pagination.
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	limit := int(req.Limit)
	actionVerbs := []string{types.VerbList, types.VerbRead}
	switch req.ResourceType {
	case types.KindNode:
		// We are checking list only for Nodes to keep backwards compatibility.
		// The read verb got added to GetNodes initially in:
		//   https://github.com/gravitational/teleport/pull/1209
		// but got removed shortly afterwards in:
		//   https://github.com/gravitational/teleport/pull/1224
		actionVerbs = []string{types.VerbList}

	default:
		return nil, trace.NotImplemented("resource type %s does not support pagination", req.ResourceType)
	}

	if err := a.action(req.Namespace, req.ResourceType, actionVerbs...); err != nil {
		return nil, trace.Wrap(err)
	}

	// Perform the label/search/expr filtering here (instead of at the backend
	// `ListResources`) to ensure that it will be applied only to resources
	// the user has access to.
	filter := services.MatchResourceFilter{
		ResourceKind:        req.ResourceType,
		Labels:              req.Labels,
		SearchKeywords:      req.SearchKeywords,
		PredicateExpression: req.PredicateExpression,
	}
	req.Labels = nil
	req.SearchKeywords = nil
	req.PredicateExpression = ""

	resourceChecker, err := a.newResourceAccessChecker(req.ResourceType)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var resp types.ListResourcesResponse
	if err := a.authServer.IterateResources(ctx, req, func(resource types.ResourceWithLabels) error {
		if len(resp.Resources) == limit {
			resp.NextKey = backend.GetPaginationKey(resource)
			return ErrDone
		}

		if err := resourceChecker.CanAccess(resource); err != nil {
			if trace.IsAccessDenied(err) {
				return nil
			}

			return trace.Wrap(err)
		}

		switch match, err := services.MatchResourceByFilters(resource, filter, nil /* ignore dup matches  */); {
		case err != nil:
			return trace.Wrap(err)
		case match:
			resp.Resources = append(resp.Resources, resource)
			return nil
		}

		return nil
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	return &resp, nil
}

// resourceAccessChecker allows access to be checked differently per resource type.
type resourceAccessChecker interface {
	CanAccess(resource types.Resource) error
}

// resourceChecker is a pass through checker that utilizes the provided
// services.AccessChecker to check access
type resourceChecker struct {
	services.AccessChecker
}

// CanAccess handles providing the proper services.AccessCheckable resource
// to the services.AccessChecker
func (r resourceChecker) CanAccess(resource types.Resource) error {
	// MFA is not required for operations on app resources but
	// will be enforced at the connection time.
	mfaParams := services.AccessMFAParams{Verified: true}
	switch rr := resource.(type) {
	case types.Server:
		return r.CheckAccess(rr, mfaParams)
	default:
		return trace.BadParameter("could not check access to resource type %T", r)
	}
}

// newResourceAccessChecker creates a resourceAccessChecker for the provided resource type
func (a *ServerWithRoles) newResourceAccessChecker(resource string) (resourceAccessChecker, error) {
	switch resource {
	case types.KindNode:
		return &resourceChecker{AccessChecker: a.context.Checker}, nil
	default:
		return nil, trace.BadParameter("could not check access to resource type %s", resource)
	}
}

// listResourcesWithSort retrieves all resources of a certain resource type with rbac applied
// then afterwards applies request sorting and filtering.
func (a *ServerWithRoles) listResourcesWithSort(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	var resources []types.ResourceWithLabels
	switch req.ResourceType {
	case types.KindNode:
		nodes, err := a.GetNodes(ctx, req.Namespace)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		servers := types.Servers(nodes)
		if err := servers.SortByCustom(req.SortBy); err != nil {
			return nil, trace.Wrap(err)
		}
		resources = servers.AsResources()
	default:
		return nil, trace.NotImplemented("resource type %q is not supported for listResourcesWithSort", req.ResourceType)
	}

	// Apply request filters and get pagination info.
	resp, err := local.FakePaginate(resources, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return resp, nil
}

func (a *ServerWithRoles) UpsertAuthServer(s types.Server) error {
	if err := a.action(apidefaults.Namespace, types.KindAuthServer, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertAuthServer(s)
}

func (a *ServerWithRoles) GetAuthServers() ([]types.Server, error) {
	if err := a.action(apidefaults.Namespace, types.KindAuthServer, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetAuthServers()
}

// DeleteAllAuthServers deletes all auth servers
func (a *ServerWithRoles) DeleteAllAuthServers() error {
	if err := a.action(apidefaults.Namespace, types.KindAuthServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAllAuthServers()
}

// DeleteAuthServer deletes auth server by name
func (a *ServerWithRoles) DeleteAuthServer(name string) error {
	if err := a.action(apidefaults.Namespace, types.KindAuthServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAuthServer(name)
}

func (a *ServerWithRoles) UpsertProxy(s types.Server) error {
	if err := a.action(apidefaults.Namespace, types.KindProxy, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertProxy(s)
}

func (a *ServerWithRoles) GetProxies() ([]types.Server, error) {
	if err := a.action(apidefaults.Namespace, types.KindProxy, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetProxies()
}

// DeleteAllProxies deletes all proxies
func (a *ServerWithRoles) DeleteAllProxies() error {
	if err := a.action(apidefaults.Namespace, types.KindProxy, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAllProxies()
}

// DeleteProxy deletes proxy by name
func (a *ServerWithRoles) DeleteProxy(name string) error {
	if err := a.action(apidefaults.Namespace, types.KindProxy, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteProxy(name)
}

func (a *ServerWithRoles) UpsertReverseTunnel(r types.ReverseTunnel) error {
	if err := a.action(apidefaults.Namespace, types.KindReverseTunnel, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertReverseTunnel(r)
}

func (a *ServerWithRoles) GetReverseTunnel(name string, opts ...services.MarshalOption) (types.ReverseTunnel, error) {
	if err := a.action(apidefaults.Namespace, types.KindReverseTunnel, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetReverseTunnel(name, opts...)
}

func (a *ServerWithRoles) GetReverseTunnels(ctx context.Context, opts ...services.MarshalOption) ([]types.ReverseTunnel, error) {
	if err := a.action(apidefaults.Namespace, types.KindReverseTunnel, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetReverseTunnels(ctx, opts...)
}

func (a *ServerWithRoles) DeleteReverseTunnel(domainName string) error {
	if err := a.action(apidefaults.Namespace, types.KindReverseTunnel, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteReverseTunnel(domainName)
}

func (a *ServerWithRoles) DeleteToken(ctx context.Context, token string) error {
	if err := a.action(apidefaults.Namespace, types.KindToken, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteToken(ctx, token)
}

func (a *ServerWithRoles) GetTokens(ctx context.Context) ([]types.ProvisionToken, error) {
	if err := a.action(apidefaults.Namespace, types.KindToken, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetTokens(ctx)
}

func (a *ServerWithRoles) GetToken(ctx context.Context, token string) (types.ProvisionToken, error) {
	// The Proxy has permission to look up tokens by name in order to validate
	// attempts to use the node join script.
	if isProxy := a.hasBuiltinRole(types.RoleProxy); !isProxy {
		if err := a.action(apidefaults.Namespace, types.KindToken, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetToken(ctx, token)
}

func (a *ServerWithRoles) UpsertToken(ctx context.Context, token types.ProvisionToken) error {
	if err := a.action(apidefaults.Namespace, types.KindToken, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertToken(ctx, token)
}

func (a *ServerWithRoles) CreateToken(ctx context.Context, token types.ProvisionToken) error {
	if err := a.action(apidefaults.Namespace, types.KindToken, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CreateToken(ctx, token)
}

// GetWebToken returns the web token specified with req.
// Implements auth.ReadAccessPoint.
func (a *ServerWithRoles) GetWebToken(ctx context.Context, req types.GetWebTokenRequest) (types.WebToken, error) {
	return a.WebTokens().Get(ctx, req)
}

// WebTokens returns the web token manager.
// Implements services.WebTokensGetter.
func (a *ServerWithRoles) WebTokens() types.WebTokenInterface {
	return &webTokensWithRoles{c: a, t: a.authServer.WebTokens()}
}

// Get returns the web token specified with req.
func (r *webTokensWithRoles) Get(ctx context.Context, req types.GetWebTokenRequest) (types.WebToken, error) {
	if err := r.c.currentUserAction(req.User); err != nil {
		if err := r.c.action(apidefaults.Namespace, types.KindWebToken, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return r.t.Get(ctx, req)
}

// List returns the list of all web tokens.
func (r *webTokensWithRoles) List(ctx context.Context) ([]types.WebToken, error) {
	if err := r.c.action(apidefaults.Namespace, types.KindWebToken, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return r.t.List(ctx)
}

// Upsert creates a new or updates the existing web token from the specified token.
// TODO(dmitri): this is currently only implemented for local invocations. This needs to be
// moved into a more appropriate API
func (*webTokensWithRoles) Upsert(ctx context.Context, session types.WebToken) error {
	return trace.NotImplemented(notImplementedMessage)
}

// Delete removes the web token specified with req.
func (r *webTokensWithRoles) Delete(ctx context.Context, req types.DeleteWebTokenRequest) error {
	if err := r.c.currentUserAction(req.User); err != nil {
		if err := r.c.action(apidefaults.Namespace, types.KindWebToken, types.VerbDelete); err != nil {
			return trace.Wrap(err)
		}
	}
	return r.t.Delete(ctx, req)
}

// DeleteAll removes all web tokens.
func (r *webTokensWithRoles) DeleteAll(ctx context.Context) error {
	if err := r.c.action(apidefaults.Namespace, types.KindWebToken, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := r.c.action(apidefaults.Namespace, types.KindWebToken, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return r.t.DeleteAll(ctx)
}

type webTokensWithRoles struct {
	c accessChecker
	t types.WebTokenInterface
}

type accessChecker interface {
	action(namespace, resource string, verbs ...string) error
	currentUserAction(user string) error
}

func (a *ServerWithRoles) GetAccessRequests(ctx context.Context, filter types.AccessRequestFilter) ([]types.AccessRequest, error) {
	// users can always view their own access requests
	if filter.User != "" && a.currentUserAction(filter.User) == nil {
		return a.authServer.GetAccessRequests(ctx, filter)
	}

	// users with read + list permissions can get all requests
	if a.withOptions(quietAction(true)).action(apidefaults.Namespace, types.KindAccessRequest, types.VerbList) == nil {
		if a.withOptions(quietAction(true)).action(apidefaults.Namespace, types.KindAccessRequest, types.VerbRead) == nil {
			return a.authServer.GetAccessRequests(ctx, filter)
		}
	}

	// user does not have read/list permissions and is not specifically requesting only
	// their own requests.  we therefore subselect the filter results to show only those requests
	// that the user *is* allowed to see (specifically, their own requests + requests that they
	// are allowed to review).

	reqs, err := a.authServer.GetAccessRequests(ctx, filter)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// filter in place
	filtered := reqs[:0]
	for _, req := range reqs {
		if req.GetUser() == a.context.User.GetName() {
			filtered = append(filtered, req)
			continue
		}
	}
	return filtered, nil
}

func (a *ServerWithRoles) CreateAccessRequest(ctx context.Context, req types.AccessRequest) error {
	// An exception is made to allow users to create access *pending* requests for themselves.
	if !req.GetState().IsPending() || a.currentUserAction(req.GetUser()) != nil {
		if err := a.action(apidefaults.Namespace, types.KindAccessRequest, types.VerbCreate); err != nil {
			return trace.Wrap(err)
		}
	}
	// Ensure that an access request cannot outlive the identity that creates it.
	if req.GetAccessExpiry().Before(a.authServer.GetClock().Now()) || req.GetAccessExpiry().After(a.context.Identity.GetIdentity().Expires) {
		req.SetAccessExpiry(a.context.Identity.GetIdentity().Expires)
	}
	return a.authServer.CreateAccessRequest(ctx, req)
}

func (a *ServerWithRoles) SetAccessRequestState(ctx context.Context, params types.AccessRequestUpdate) error {
	if err := a.action(apidefaults.Namespace, types.KindAccessRequest, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.SetAccessRequestState(ctx, params)
}

// GetPluginData loads all plugin data matching the supplied filter.
func (a *ServerWithRoles) GetPluginData(ctx context.Context, filter types.PluginDataFilter) ([]types.PluginData, error) {
	switch filter.Kind {
	case types.KindAccessRequest:
		// for backwards compatibility, we allow list/read against access requests to also grant list/read for
		// access request related plugin data.
		if a.withOptions(quietAction(true)).action(apidefaults.Namespace, types.KindAccessRequest, types.VerbList) != nil {
			if err := a.action(apidefaults.Namespace, types.KindAccessPluginData, types.VerbList); err != nil {
				return nil, trace.Wrap(err)
			}
		}
		if a.withOptions(quietAction(true)).action(apidefaults.Namespace, types.KindAccessRequest, types.VerbRead) != nil {
			if err := a.action(apidefaults.Namespace, types.KindAccessPluginData, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		}
		return a.authServer.GetPluginData(ctx, filter)
	default:
		return nil, trace.BadParameter("unsupported resource kind %q", filter.Kind)
	}
}

// UpdatePluginData updates a per-resource PluginData entry.
func (a *ServerWithRoles) UpdatePluginData(ctx context.Context, params types.PluginDataUpdateParams) error {
	switch params.Kind {
	case types.KindAccessRequest:
		// for backwards compatibility, we allow update against access requests to also grant update for
		// access request related plugin data.
		if a.withOptions(quietAction(true)).action(apidefaults.Namespace, types.KindAccessRequest, types.VerbUpdate) != nil {
			if err := a.action(apidefaults.Namespace, types.KindAccessPluginData, types.VerbUpdate); err != nil {
				return trace.Wrap(err)
			}
		}
		return a.authServer.UpdatePluginData(ctx, params)
	default:
		return trace.BadParameter("unsupported resource kind %q", params.Kind)
	}
}

// Ping gets basic info about the auth server.
func (a *ServerWithRoles) Ping(ctx context.Context) (proto.PingResponse, error) {
	// The Ping method does not require special permissions since it only returns
	// basic status information.  This is an intentional design choice.  Alternative
	// methods should be used for relaying any sensitive information.
	cn, err := a.authServer.GetClusterName()
	if err != nil {
		return proto.PingResponse{}, trace.Wrap(err)
	}

	return proto.PingResponse{
		ClusterName:     cn.GetClusterName(),
		ServerVersion:   teleport.Version,
		ServerFeatures:  modules.GetModules().Features().ToProto(),
		ProxyPublicAddr: a.getProxyPublicAddr(),
		IsBoring:        modules.GetModules().IsBoringBinary(),
	}, nil
}

// getProxyPublicAddr gets the server's public proxy address.
func (a *ServerWithRoles) getProxyPublicAddr() string {
	if proxies, err := a.authServer.GetProxies(); err == nil {
		for _, p := range proxies {
			addr := p.GetPublicAddr()
			if addr == "" {
				continue
			}
			if _, err := utils.ParseAddr(addr); err != nil {
				log.Warningf("Invalid public address on the proxy %q: %q: %v.", p.GetName(), addr, err)
				continue
			}
			return addr
		}
	}
	return ""
}

func (a *ServerWithRoles) DeleteAccessRequest(ctx context.Context, name string) error {
	if err := a.action(apidefaults.Namespace, types.KindAccessRequest, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAccessRequest(ctx, name)
}

// GetCurrentUser returns current user as seen by the server.
// Useful especially in the context of remote clusters which perform role and trait mapping.
func (a *ServerWithRoles) GetCurrentUser(ctx context.Context) (types.User, error) {
	// check access to roles
	for _, role := range a.context.User.GetRoles() {
		_, err := a.GetRole(ctx, role)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	usrRes := a.context.User.WithoutSecrets()
	if usr, ok := usrRes.(types.User); ok {
		return usr, nil
	}
	return nil, trace.BadParameter("expected types.User when fetching current user information, got %T", usrRes)
}

// GetCurrentUserRoles returns current user's roles.
func (a *ServerWithRoles) GetCurrentUserRoles(ctx context.Context) ([]types.Role, error) {
	roleNames := a.context.User.GetRoles()
	roles := make([]types.Role, 0, len(roleNames))
	for _, roleName := range roleNames {
		role, err := a.GetRole(ctx, roleName)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (a *ServerWithRoles) GenerateHostCert(
	key []byte, hostID, nodeName string, principals []string, clusterName string, role types.SystemRole, ttl time.Duration,
) ([]byte, error) {
	ctx := services.Context{
		User: a.context.User,
		HostCert: &services.HostCertContext{
			HostID:      hostID,
			NodeName:    nodeName,
			Principals:  principals,
			ClusterName: clusterName,
			Role:        role,
			TTL:         ttl,
		},
	}

	// Instead of the usual RBAC checks, we'll manually call CheckAccessToRule
	// here as we'll be evaluating `where` predicates with a custom RuleContext
	// to expose cert request fields.
	// We've only got a single verb to check so luckily it's pretty concise.
	if err := a.withOptions().context.Checker.CheckAccessToRule(
		&ctx, apidefaults.Namespace, types.KindHostCert, types.VerbCreate, false,
	); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.GenerateHostCert(key, hostID, nodeName, principals, clusterName, role, ttl)
}

// NewKeepAliver not implemented: can only be called locally.
func (a *ServerWithRoles) NewKeepAliver(ctx context.Context) (types.KeepAliver, error) {
	return nil, trace.NotImplemented(notImplementedMessage)
}

// EmitAuditEvent emits a single audit event
func (a *ServerWithRoles) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	if err := a.action(apidefaults.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return trace.AccessDenied("this request can be only executed by a teleport built-in server")
	}
	err := events.ValidateServerMetadata(event, role.GetServerID(), a.hasBuiltinRole(types.RoleProxy))
	if err != nil {
		// TODO: this should be a proper audit event
		// notifying about access violation
		log.Warningf("Rejecting audit event %v(%q) from %q: %v. The client is attempting to "+
			"submit events for an identity other than the one on its x509 certificate.",
			event.GetType(), event.GetID(), role.GetServerID(), err)
		// this message is sparse on purpose to avoid conveying extra data to an attacker
		return trace.AccessDenied("failed to validate event metadata")
	}
	return a.authServer.emitter.EmitAuditEvent(ctx, event)
}

// CreateAuditStream creates audit event stream
func (a *ServerWithRoles) CreateAuditStream(ctx context.Context, sid session.ID) (apievents.Stream, error) {
	if err := a.action(apidefaults.Namespace, types.KindEvent, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return nil, trace.AccessDenied("this request can be only executed by proxy, node or auth")
	}
	stream, err := a.authServer.CreateAuditStream(ctx, sid)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &streamWithRoles{
		stream:   stream,
		a:        a,
		serverID: role.GetServerID(),
	}, nil
}

// ResumeAuditStream resumes the stream that has been created
func (a *ServerWithRoles) ResumeAuditStream(ctx context.Context, sid session.ID, uploadID string) (apievents.Stream, error) {
	if err := a.action(apidefaults.Namespace, types.KindEvent, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return nil, trace.AccessDenied("this request can be only executed by proxy, node or auth")
	}
	stream, err := a.authServer.ResumeAuditStream(ctx, sid, uploadID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &streamWithRoles{
		stream:   stream,
		a:        a,
		serverID: role.GetServerID(),
	}, nil
}

type streamWithRoles struct {
	a        *ServerWithRoles
	serverID string
	stream   apievents.Stream
}

// Status returns channel receiving updates about stream status
// last event index that was uploaded and upload ID
func (s *streamWithRoles) Status() <-chan apievents.StreamStatus {
	return s.stream.Status()
}

// Done returns channel closed when streamer is closed
// should be used to detect sending errors
func (s *streamWithRoles) Done() <-chan struct{} {
	return s.stream.Done()
}

// Complete closes the stream and marks it finalized
func (s *streamWithRoles) Complete(ctx context.Context) error {
	return s.stream.Complete(ctx)
}

// Close flushes non-uploaded flight stream data without marking
// the stream completed and closes the stream instance
func (s *streamWithRoles) Close(ctx context.Context) error {
	return s.stream.Close(ctx)
}

func (s *streamWithRoles) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	err := events.ValidateServerMetadata(event, s.serverID, s.a.hasBuiltinRole(types.RoleProxy))
	if err != nil {
		// TODO: this should be a proper audit event
		// notifying about access violation
		log.Warningf("Rejecting audit event %v from %v: %v. A node is attempting to "+
			"submit events for an identity other than the one on its x509 certificate.",
			event.GetID(), s.serverID, err)
		// this message is sparse on purpose to avoid conveying extra data to an attacker
		return trace.AccessDenied("failed to validate event metadata")
	}
	return s.stream.EmitAuditEvent(ctx, event)
}

func (a *ServerWithRoles) GetSessionChunk(namespace string, sid session.ID, offsetBytes, maxBytes int) ([]byte, error) {
	if err := a.actionForKindSession(namespace, types.VerbRead, sid); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.alog.GetSessionChunk(namespace, sid, offsetBytes, maxBytes)
}

func (a *ServerWithRoles) GetSessionEvents(namespace string, sid session.ID, afterN int, includePrintEvents bool) ([]events.EventFields, error) {
	if err := a.actionForKindSession(namespace, types.VerbRead, sid); err != nil {
		return nil, trace.Wrap(err)
	}

	// emit a session recording view event for the audit log
	if err := a.authServer.emitter.EmitAuditEvent(a.authServer.closeCtx, &apievents.SessionRecordingAccess{
		Metadata: apievents.Metadata{
			Type: events.SessionRecordingAccessEvent,
			Code: events.SessionRecordingAccessCode,
		},
		SessionID:    sid.String(),
		UserMetadata: a.context.Identity.GetIdentity().GetUserMetadata(),
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.alog.GetSessionEvents(namespace, sid, afterN, includePrintEvents)
}

func (a *ServerWithRoles) findSessionEndEvent(namespace string, sid session.ID) (apievents.AuditEvent, error) {
	sessionEvents, _, err := a.alog.SearchSessionEvents(time.Time{}, a.authServer.clock.Now().UTC(),
		defaults.EventsIterationLimit, types.EventOrderAscending, "",
		&types.WhereExpr{Equals: types.WhereExpr2{
			L: &types.WhereExpr{Field: events.SessionEventID},
			R: &types.WhereExpr{Literal: sid.String()},
		}}, sid.String(),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(sessionEvents) == 1 {
		return sessionEvents[0], nil
	}

	return nil, trace.NotFound("session end event not found for session ID %q", sid)
}

// GetNamespaces returns a list of namespaces
func (a *ServerWithRoles) GetNamespaces() ([]types.Namespace, error) {
	if err := a.action(apidefaults.Namespace, types.KindNamespace, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNamespaces()
}

// GetNamespace returns namespace by name
func (a *ServerWithRoles) GetNamespace(name string) (*types.Namespace, error) {
	if err := a.action(apidefaults.Namespace, types.KindNamespace, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNamespace(name)
}

// UpsertNamespace upserts namespace
func (a *ServerWithRoles) UpsertNamespace(ns types.Namespace) error {
	if err := a.action(apidefaults.Namespace, types.KindNamespace, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertNamespace(ns)
}

// DeleteNamespace deletes namespace by name
func (a *ServerWithRoles) DeleteNamespace(name string) error {
	if err := a.action(apidefaults.Namespace, types.KindNamespace, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteNamespace(name)
}

// GetRoles returns a list of roles
func (a *ServerWithRoles) GetRoles(ctx context.Context) ([]types.Role, error) {
	if err := a.action(apidefaults.Namespace, types.KindRole, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetRoles(ctx)
}

// CreateRole not implemented: can only be called locally.
func (a *ServerWithRoles) CreateRole(ctx context.Context, role types.Role) error {
	return trace.NotImplemented(notImplementedMessage)
}

// UpsertRole creates or updates role.
func (a *ServerWithRoles) UpsertRole(ctx context.Context, role types.Role) error {
	if err := a.action(apidefaults.Namespace, types.KindRole, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	// Some options are only available with enterprise subscription
	if err := checkRoleFeatureSupport(role); err != nil {
		return trace.Wrap(err)
	}

	// access predicate syntax is not checked as part of normal role validation in order
	// to allow the available namespaces to be extended without breaking compatibility with
	// older nodes/proxies (which do not need to ever evaluate said predicates).
	if err := services.ValidateAccessPredicates(role); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.UpsertRole(ctx, role)
}

func checkRoleFeatureSupport(role types.Role) error {
	features := modules.GetModules().Features()
	options := role.GetOptions()
	allowReq, allowRev := role.GetAccessRequestConditions(types.Allow), role.GetAccessReviewConditions(types.Allow)

	// source IP pinning doesn't have a dedicated feature flag,
	// it is available to all enterprise users
	if modules.GetModules().BuildType() != modules.BuildEnterprise && role.GetOptions().PinSourceIP {
		return trace.AccessDenied("role option pin_source_ip is only available in enterprise subscriptions")
	}

	switch {
	case !features.AccessControls && options.MaxSessions > 0:
		return trace.AccessDenied(
			"role option max_sessions is only available in enterprise subscriptions")
	case !features.AdvancedAccessWorkflows &&
		(options.RequestAccess == types.RequestStrategyReason || options.RequestAccess == types.RequestStrategyAlways):
		return trace.AccessDenied(
			"role option request_access: %v is only available in enterprise subscriptions", options.RequestAccess)
	case !features.AdvancedAccessWorkflows && len(allowReq.Thresholds) != 0:
		return trace.AccessDenied(
			"role field allow.request.thresholds is only available in enterprise subscriptions")
	case !features.AdvancedAccessWorkflows && !allowRev.IsZero():
		return trace.AccessDenied(
			"role field allow.review_requests is only available in enterprise subscriptions")
	case !features.ResourceAccessRequests && len(allowReq.SearchAsRoles) != 0:
		return trace.AccessDenied(
			"role field allow.search_as_roles is only available in enterprise subscriptions licensed for resource access requests")
	default:
		return nil
	}
}

// GetRole returns role by name
func (a *ServerWithRoles) GetRole(ctx context.Context, name string) (types.Role, error) {
	// Current-user exception: we always allow users to read roles
	// that they hold.  This requirement is checked first to avoid
	// misleading denial messages in the logs.
	if !apiutils.SliceContainsStr(a.context.User.GetRoles(), name) {
		if err := a.action(apidefaults.Namespace, types.KindRole, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetRole(ctx, name)
}

// DeleteRole deletes role by name
func (a *ServerWithRoles) DeleteRole(ctx context.Context, name string) error {
	if err := a.action(apidefaults.Namespace, types.KindRole, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	// DELETE IN (7.0)
	// It's OK to delete this code alongside migrateOSS code in auth.
	// It prevents 6.0 from migrating resources multiple times
	// and the role is used for `tctl users add` code too.
	if modules.GetModules().BuildType() == modules.BuildOSS && name == teleport.AdminRoleName {
		return trace.AccessDenied("can not delete system role %q", name)
	}
	return a.authServer.DeleteRole(ctx, name)
}

// DeleteClusterName deletes cluster name
func (a *ServerWithRoles) DeleteClusterName() error {
	if err := a.action(apidefaults.Namespace, types.KindClusterName, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteClusterName()
}

// GetClusterName gets the name of the cluster.
func (a *ServerWithRoles) GetClusterName(opts ...services.MarshalOption) (types.ClusterName, error) {
	if err := a.action(apidefaults.Namespace, types.KindClusterName, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetClusterName()
}

// SetClusterName sets the name of the cluster. SetClusterName can only be called once.
func (a *ServerWithRoles) SetClusterName(c types.ClusterName) error {
	if err := a.action(apidefaults.Namespace, types.KindClusterName, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.SetClusterName(c)
}

// UpsertClusterName sets the name of the cluster.
func (a *ServerWithRoles) UpsertClusterName(c types.ClusterName) error {
	if err := a.action(apidefaults.Namespace, types.KindClusterName, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertClusterName(c)
}

// DeleteStaticTokens deletes static tokens
func (a *ServerWithRoles) DeleteStaticTokens() error {
	if err := a.action(apidefaults.Namespace, types.KindStaticTokens, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteStaticTokens()
}

// GetStaticTokens gets the list of static tokens used to provision nodes.
func (a *ServerWithRoles) GetStaticTokens() (types.StaticTokens, error) {
	if err := a.action(apidefaults.Namespace, types.KindStaticTokens, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetStaticTokens()
}

// SetStaticTokens sets the list of static tokens used to provision nodes.
func (a *ServerWithRoles) SetStaticTokens(s types.StaticTokens) error {
	if err := a.action(apidefaults.Namespace, types.KindStaticTokens, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.SetStaticTokens(s)
}

// GetAuthPreference gets cluster auth preference.
func (a *ServerWithRoles) GetAuthPreference(ctx context.Context) (types.AuthPreference, error) {
	if err := a.action(apidefaults.Namespace, types.KindClusterAuthPreference, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.GetAuthPreference(ctx)
}

// SetAuthPreference sets cluster auth preference.
func (a *ServerWithRoles) SetAuthPreference(ctx context.Context, newAuthPref types.AuthPreference) error {
	storedAuthPref, err := a.authServer.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := a.action(apidefaults.Namespace, types.KindClusterAuthPreference, verbsToReplaceResourceWithOrigin(storedAuthPref)...); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.SetAuthPreference(ctx, newAuthPref)
}

// ResetAuthPreference resets cluster auth preference to defaults.
func (a *ServerWithRoles) ResetAuthPreference(ctx context.Context) error {
	storedAuthPref, err := a.authServer.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if storedAuthPref.Origin() == types.OriginConfigFile {
		return trace.BadParameter("config-file configuration cannot be reset")
	}

	if err := a.action(apidefaults.Namespace, types.KindClusterAuthPreference, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.SetAuthPreference(ctx, types.DefaultAuthPreference())
}

// DeleteAuthPreference not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAuthPreference(context.Context) error {
	return trace.NotImplemented(notImplementedMessage)
}

// GetClusterAuditConfig gets cluster audit configuration.
func (a *ServerWithRoles) GetClusterAuditConfig(ctx context.Context, opts ...services.MarshalOption) (types.ClusterAuditConfig, error) {
	if err := a.action(apidefaults.Namespace, types.KindClusterAuditConfig, types.VerbRead); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, types.VerbRead); err2 != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetClusterAuditConfig(ctx, opts...)
}

// SetClusterAuditConfig not implemented: can only be called locally.
func (a *ServerWithRoles) SetClusterAuditConfig(ctx context.Context, auditConfig types.ClusterAuditConfig) error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteClusterAuditConfig not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteClusterAuditConfig(ctx context.Context) error {
	return trace.NotImplemented(notImplementedMessage)
}

// GetClusterNetworkingConfig gets cluster networking configuration.
func (a *ServerWithRoles) GetClusterNetworkingConfig(ctx context.Context, opts ...services.MarshalOption) (types.ClusterNetworkingConfig, error) {
	if err := a.action(apidefaults.Namespace, types.KindClusterNetworkingConfig, types.VerbRead); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, types.VerbRead); err2 != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetClusterNetworkingConfig(ctx, opts...)
}

// SetClusterNetworkingConfig sets cluster networking configuration.
func (a *ServerWithRoles) SetClusterNetworkingConfig(ctx context.Context, newNetConfig types.ClusterNetworkingConfig) error {
	storedNetConfig, err := a.authServer.GetClusterNetworkingConfig(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := a.action(apidefaults.Namespace, types.KindClusterNetworkingConfig, verbsToReplaceResourceWithOrigin(storedNetConfig)...); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, verbsToReplaceResourceWithOrigin(storedNetConfig)...); err2 != nil {
			return trace.Wrap(err)
		}
	}

	tst, err := newNetConfig.GetTunnelStrategyType()
	if err != nil {
		return trace.Wrap(err)
	}
	if tst == types.ProxyPeering &&
		modules.GetModules().BuildType() != modules.BuildEnterprise {
		return trace.AccessDenied("proxy peering is an enterprise-only feature")
	}

	return a.authServer.SetClusterNetworkingConfig(ctx, newNetConfig)
}

// ResetClusterNetworkingConfig resets cluster networking configuration to defaults.
func (a *ServerWithRoles) ResetClusterNetworkingConfig(ctx context.Context) error {
	storedNetConfig, err := a.authServer.GetClusterNetworkingConfig(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if storedNetConfig.Origin() == types.OriginConfigFile {
		return trace.BadParameter("config-file configuration cannot be reset")
	}

	if err := a.action(apidefaults.Namespace, types.KindClusterNetworkingConfig, types.VerbUpdate); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, types.VerbUpdate); err2 != nil {
			return trace.Wrap(err)
		}
	}

	return a.authServer.SetClusterNetworkingConfig(ctx, types.DefaultClusterNetworkingConfig())
}

// DeleteClusterNetworkingConfig not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteClusterNetworkingConfig(ctx context.Context) error {
	return trace.NotImplemented(notImplementedMessage)
}

// GetSessionRecordingConfig gets session recording configuration.
func (a *ServerWithRoles) GetSessionRecordingConfig(ctx context.Context, opts ...services.MarshalOption) (types.SessionRecordingConfig, error) {
	if err := a.action(apidefaults.Namespace, types.KindSessionRecordingConfig, types.VerbRead); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, types.VerbRead); err2 != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetSessionRecordingConfig(ctx, opts...)
}

// SetSessionRecordingConfig sets session recording configuration.
func (a *ServerWithRoles) SetSessionRecordingConfig(ctx context.Context, newRecConfig types.SessionRecordingConfig) error {
	storedRecConfig, err := a.authServer.GetSessionRecordingConfig(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := a.action(apidefaults.Namespace, types.KindSessionRecordingConfig, verbsToReplaceResourceWithOrigin(storedRecConfig)...); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, verbsToReplaceResourceWithOrigin(storedRecConfig)...); err2 != nil {
			return trace.Wrap(err)
		}
	}

	return a.authServer.SetSessionRecordingConfig(ctx, newRecConfig)
}

// ResetSessionRecordingConfig resets session recording configuration to defaults.
func (a *ServerWithRoles) ResetSessionRecordingConfig(ctx context.Context) error {
	storedRecConfig, err := a.authServer.GetSessionRecordingConfig(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if storedRecConfig.Origin() == types.OriginConfigFile {
		return trace.BadParameter("config-file configuration cannot be reset")
	}

	if err := a.action(apidefaults.Namespace, types.KindSessionRecordingConfig, types.VerbUpdate); err != nil {
		if err2 := a.action(apidefaults.Namespace, types.KindClusterConfig, types.VerbUpdate); err2 != nil {
			return trace.Wrap(err)
		}
	}

	return a.authServer.SetSessionRecordingConfig(ctx, types.DefaultSessionRecordingConfig())
}

// DeleteSessionRecordingConfig not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteSessionRecordingConfig(ctx context.Context) error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteAllTokens not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllTokens() error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteAllCertAuthorities not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllCertAuthorities(caType types.CertAuthType) error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteAllCertNamespaces not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllNamespaces() error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteAllReverseTunnels not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllReverseTunnels() error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteAllRoles not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllRoles() error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeleteAllUsers not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllUsers() error {
	return trace.NotImplemented(notImplementedMessage)
}

func (a *ServerWithRoles) GetTrustedClusters(ctx context.Context) ([]types.TrustedCluster, error) {
	if err := a.action(apidefaults.Namespace, types.KindTrustedCluster, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.GetTrustedClusters(ctx)
}

func (a *ServerWithRoles) GetTrustedCluster(ctx context.Context, name string) (types.TrustedCluster, error) {
	if err := a.action(apidefaults.Namespace, types.KindTrustedCluster, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.GetTrustedCluster(ctx, name)
}

// UpsertTrustedCluster creates or updates a trusted cluster.
func (a *ServerWithRoles) UpsertTrustedCluster(ctx context.Context, tc types.TrustedCluster) (types.TrustedCluster, error) {
	if err := a.action(apidefaults.Namespace, types.KindTrustedCluster, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.UpsertTrustedCluster(ctx, tc)
}

// DeleteTrustedCluster deletes a trusted cluster by name.
func (a *ServerWithRoles) DeleteTrustedCluster(ctx context.Context, name string) error {
	if err := a.action(apidefaults.Namespace, types.KindTrustedCluster, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.DeleteTrustedCluster(ctx, name)
}

func (a *ServerWithRoles) UpsertTunnelConnection(conn types.TunnelConnection) error {
	if err := a.action(apidefaults.Namespace, types.KindTunnelConnection, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertTunnelConnection(conn)
}

func (a *ServerWithRoles) GetTunnelConnections(clusterName string, opts ...services.MarshalOption) ([]types.TunnelConnection, error) {
	if err := a.action(apidefaults.Namespace, types.KindTunnelConnection, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetTunnelConnections(clusterName, opts...)
}

func (a *ServerWithRoles) GetAllTunnelConnections(opts ...services.MarshalOption) ([]types.TunnelConnection, error) {
	if err := a.action(apidefaults.Namespace, types.KindTunnelConnection, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetAllTunnelConnections(opts...)
}

func (a *ServerWithRoles) DeleteTunnelConnection(clusterName string, connName string) error {
	if err := a.action(apidefaults.Namespace, types.KindTunnelConnection, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteTunnelConnection(clusterName, connName)
}

func (a *ServerWithRoles) DeleteTunnelConnections(clusterName string) error {
	if err := a.action(apidefaults.Namespace, types.KindTunnelConnection, types.VerbList, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteTunnelConnections(clusterName)
}

func (a *ServerWithRoles) DeleteAllTunnelConnections() error {
	if err := a.action(apidefaults.Namespace, types.KindTunnelConnection, types.VerbList, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAllTunnelConnections()
}

func (a *ServerWithRoles) CreateRemoteCluster(conn types.RemoteCluster) error {
	if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CreateRemoteCluster(conn)
}

func (a *ServerWithRoles) UpdateRemoteCluster(ctx context.Context, rc types.RemoteCluster) error {
	if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpdateRemoteCluster(ctx, rc)
}

func (a *ServerWithRoles) GetRemoteCluster(clusterName string) (types.RemoteCluster, error) {
	if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	cluster, err := a.authServer.GetRemoteCluster(clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.context.Checker.CheckAccessToRemoteCluster(cluster); err != nil {
		return nil, utils.OpaqueAccessDenied(err)
	}
	return cluster, nil
}

func (a *ServerWithRoles) GetRemoteClusters(opts ...services.MarshalOption) ([]types.RemoteCluster, error) {
	if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	remoteClusters, err := a.authServer.GetRemoteClusters(opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.filterRemoteClustersForUser(remoteClusters)
}

// filterRemoteClustersForUser filters remote clusters based on what the current user is authorized to access
func (a *ServerWithRoles) filterRemoteClustersForUser(remoteClusters []types.RemoteCluster) ([]types.RemoteCluster, error) {
	filteredClusters := make([]types.RemoteCluster, 0, len(remoteClusters))
	for _, rc := range remoteClusters {
		if err := a.context.Checker.CheckAccessToRemoteCluster(rc); err != nil {
			if trace.IsAccessDenied(err) {
				continue
			}
			return nil, trace.Wrap(err)
		}
		filteredClusters = append(filteredClusters, rc)
	}
	return filteredClusters, nil
}

func (a *ServerWithRoles) DeleteRemoteCluster(clusterName string) error {
	if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteRemoteCluster(clusterName)
}

func (a *ServerWithRoles) DeleteAllRemoteClusters() error {
	if err := a.action(apidefaults.Namespace, types.KindRemoteCluster, types.VerbList, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteAllRemoteClusters()
}

// AcquireSemaphore acquires lease with requested resources from semaphore.
func (a *ServerWithRoles) AcquireSemaphore(ctx context.Context, params types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	if err := a.action(apidefaults.Namespace, types.KindSemaphore, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.AcquireSemaphore(ctx, params)
}

// KeepAliveSemaphoreLease updates semaphore lease.
func (a *ServerWithRoles) KeepAliveSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	if err := a.action(apidefaults.Namespace, types.KindSemaphore, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.KeepAliveSemaphoreLease(ctx, lease)
}

// CancelSemaphoreLease cancels semaphore lease early.
func (a *ServerWithRoles) CancelSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	if err := a.action(apidefaults.Namespace, types.KindSemaphore, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CancelSemaphoreLease(ctx, lease)
}

// GetSemaphores returns a list of all semaphores matching the supplied filter.
func (a *ServerWithRoles) GetSemaphores(ctx context.Context, filter types.SemaphoreFilter) ([]types.Semaphore, error) {
	if err := a.action(apidefaults.Namespace, types.KindSemaphore, types.VerbReadNoSecrets, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetSemaphores(ctx, filter)
}

// DeleteSemaphore deletes a semaphore matching the supplied filter.
func (a *ServerWithRoles) DeleteSemaphore(ctx context.Context, filter types.SemaphoreFilter) error {
	if err := a.action(apidefaults.Namespace, types.KindSemaphore, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteSemaphore(ctx, filter)
}

func (a *ServerWithRoles) Close() error {
	return a.authServer.Close()
}

// GetNetworkRestrictions retrieves all the network restrictions (allow/deny lists).
func (a *ServerWithRoles) GetNetworkRestrictions(ctx context.Context) (types.NetworkRestrictions, error) {
	if err := a.action(apidefaults.Namespace, types.KindNetworkRestrictions, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNetworkRestrictions(ctx)
}

// SetNetworkRestrictions updates the network restrictions.
func (a *ServerWithRoles) SetNetworkRestrictions(ctx context.Context, nr types.NetworkRestrictions) error {
	if err := a.action(apidefaults.Namespace, types.KindNetworkRestrictions, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.SetNetworkRestrictions(ctx, nr)
}

// DeleteNetworkRestrictions deletes the network restrictions.
func (a *ServerWithRoles) DeleteNetworkRestrictions(ctx context.Context) error {
	if err := a.action(apidefaults.Namespace, types.KindNetworkRestrictions, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteNetworkRestrictions(ctx)
}

// GenerateUserSingleUseCerts exists to satisfy auth.ClientI but is not
// implemented here.
//
// Use auth.GRPCServer.GenerateUserSingleUseCerts or
// client.Client.GenerateUserSingleUseCerts instead.
func (a *ServerWithRoles) GenerateUserSingleUseCerts(ctx context.Context) (proto.AuthService_GenerateUserSingleUseCertsClient, error) {
	return nil, trace.NotImplemented("bug: GenerateUserSingleUseCerts must not be called on auth.ServerWithRoles")
}

// SearchEvents allows searching audit events with pagination support.
func (a *ServerWithRoles) SearchEvents(fromUTC, toUTC time.Time, namespace string, eventTypes []string, limit int, order types.EventOrder, startKey string) (events []apievents.AuditEvent, lastKey string, err error) {
	if err := a.action(apidefaults.Namespace, types.KindEvent, types.VerbList); err != nil {
		return nil, "", trace.Wrap(err)
	}

	events, lastKey, err = a.alog.SearchEvents(fromUTC, toUTC, namespace, eventTypes, limit, order, startKey)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	return events, lastKey, nil
}

// SearchSessionEvents allows searching session audit events with pagination support.
func (a *ServerWithRoles) SearchSessionEvents(fromUTC, toUTC time.Time, limit int, order types.EventOrder, startKey string, cond *types.WhereExpr, sessionID string) (events []apievents.AuditEvent, lastKey string, err error) {
	if cond != nil {
		return nil, "", trace.BadParameter("cond is an internal parameter, should not be set by client")
	}

	cond, err = a.actionForListWithCondition(apidefaults.Namespace, types.KindSession, services.SessionIdentifier)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	// TODO(codingllama): Refactor cond out of SearchSessionEvents and simplify signature.
	events, lastKey, err = a.alog.SearchSessionEvents(fromUTC, toUTC, limit, order, startKey, cond, sessionID)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	return events, lastKey, nil
}

// GetLock gets a lock by name.
func (a *ServerWithRoles) GetLock(ctx context.Context, name string) (types.Lock, error) {
	if err := a.action(apidefaults.Namespace, types.KindLock, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetLock(ctx, name)
}

// GetLocks gets all/in-force locks that match at least one of the targets when specified.
func (a *ServerWithRoles) GetLocks(ctx context.Context, inForceOnly bool, targets ...types.LockTarget) ([]types.Lock, error) {
	if err := a.action(apidefaults.Namespace, types.KindLock, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetLocks(ctx, inForceOnly, targets...)
}

// UpsertLock upserts a lock.
func (a *ServerWithRoles) UpsertLock(ctx context.Context, lock types.Lock) error {
	if err := a.action(apidefaults.Namespace, types.KindLock, types.VerbCreate, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.UpsertLock(ctx, lock)
}

// DeleteLock deletes a lock.
func (a *ServerWithRoles) DeleteLock(ctx context.Context, name string) error {
	if err := a.action(apidefaults.Namespace, types.KindLock, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteLock(ctx, name)
}

// DeleteAllLocks not implemented: can only be called locally.
func (a *ServerWithRoles) DeleteAllLocks(context.Context) error {
	return trace.NotImplemented(notImplementedMessage)
}

// ReplaceRemoteLocks replaces the set of locks associated with a remote cluster.
func (a *ServerWithRoles) ReplaceRemoteLocks(ctx context.Context, clusterName string, locks []types.Lock) error {
	role, ok := a.context.Identity.(RemoteBuiltinRole)
	if !a.hasRemoteBuiltinRole(string(types.RoleRemoteProxy)) || !ok || role.ClusterName != clusterName {
		return trace.AccessDenied("this request can be only executed by a remote proxy of cluster %q", clusterName)
	}
	return a.authServer.ReplaceRemoteLocks(ctx, clusterName, locks)
}

// StreamSessionEvents streams all events from a given session recording. An error is returned on the first
// channel if one is encountered. Otherwise the event channel is closed when the stream ends.
// The event channel is not closed on error to prevent race conditions in downstream select statements.
func (a *ServerWithRoles) StreamSessionEvents(ctx context.Context, sessionID session.ID, startIndex int64) (chan apievents.AuditEvent, chan error) {
	createErrorChannel := func(err error) (chan apievents.AuditEvent, chan error) {
		e := make(chan error, 1)
		e <- trace.Wrap(err)
		return nil, e
	}

	if err := a.actionForKindSession(apidefaults.Namespace, types.VerbList, sessionID); err != nil {
		return createErrorChannel(err)
	}

	// StreamSessionEvents can be called internally, and when that happens we don't want to emit an event.
	shouldEmitAuditEvent := true
	if role, ok := a.context.Identity.(BuiltinRole); ok {
		if role.IsServer() {
			shouldEmitAuditEvent = false
		}
	}

	if shouldEmitAuditEvent {
		if err := a.authServer.emitter.EmitAuditEvent(a.authServer.closeCtx, &apievents.SessionRecordingAccess{
			Metadata: apievents.Metadata{
				Type: events.SessionRecordingAccessEvent,
				Code: events.SessionRecordingAccessCode,
			},
			SessionID:    sessionID.String(),
			UserMetadata: a.context.Identity.GetIdentity().GetUserMetadata(),
		}); err != nil {
			return createErrorChannel(err)
		}
	}

	return a.alog.StreamSessionEvents(ctx, sessionID, startIndex)
}

func (a *ServerWithRoles) checkAccessToNode(node types.Server) error {
	// For certain built-in roles, continue to allow full access and return
	// the full set of nodes to not break existing clusters during migration.
	//
	// In addition, allow proxy (and remote proxy) to access all nodes for its
	// smart resolution address resolution. Once the smart resolution logic is
	// moved to the auth server, this logic can be removed.
	builtinRole := HasBuiltinRole(a.context, string(types.RoleAdmin)) ||
		HasBuiltinRole(a.context, string(types.RoleProxy)) ||
		HasRemoteBuiltinRole(a.context, string(types.RoleRemoteProxy))

	if builtinRole {
		return nil
	}

	return a.context.Checker.CheckAccess(node,
		// MFA is not required for operations on node resources but
		// will be enforced at the connection time.
		services.AccessMFAParams{Verified: true})
}

// AppendDiagnosticTrace adds a new trace for the given ConnectionDiagnostic.
func (a *ServerWithRoles) AppendDiagnosticTrace(ctx context.Context, name string, t *types.ConnectionDiagnosticTrace) (types.ConnectionDiagnostic, error) {
	if err := a.action(apidefaults.Namespace, types.KindConnectionDiagnostic, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.AppendDiagnosticTrace(ctx, name, t)
}

// GenerateCertAuthorityCRL generates an empty CRL for a CA.
func (a *ServerWithRoles) GenerateCertAuthorityCRL(ctx context.Context, caType types.CertAuthType) ([]byte, error) {
	// Only windows_desktop_service should be requesting CRLs
	if !a.hasBuiltinRole(types.RoleWindowsDesktop) {
		return nil, trace.AccessDenied("access denied")
	}
	crl, err := a.authServer.GenerateCertAuthorityCRL(ctx, caType)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return crl, nil
}

// UpdatePresence is coupled to the service layer and must exist here but is never actually called
// since it's handled by the session presence task. This is never valid to call.
func (a *ServerWithRoles) UpdatePresence(ctx context.Context, sessionID, user string) error {
	return trace.NotImplemented(notImplementedMessage)
}

// UpdatePresence is coupled to the service layer and must exist here but is never actually called
// since it's handled by the session presence task. This is never valid to call.
func (a *ServerWithRoles) MaintainSessionPresence(ctx context.Context) (proto.AuthService_MaintainSessionPresenceClient, error) {
	return nil, trace.NotImplemented(notImplementedMessage)
}

// verbsToReplaceResourceWithOrigin determines the verbs/actions required of a role
// to replace the resource currently stored in the backend.
func verbsToReplaceResourceWithOrigin(stored types.ResourceWithOrigin) []string {
	verbs := []string{types.VerbUpdate}
	if stored.Origin() == types.OriginConfigFile {
		verbs = append(verbs, types.VerbCreate)
	}
	return verbs
}
