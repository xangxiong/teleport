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

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/session"

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

type actionConfig struct {
	quiet   bool
	context Context
}

type actionOption func(*actionConfig)

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

// hasLocalUserRole checks if the identity is a local user or not.
func hasLocalUserRole(authContext Context) bool {
	_, ok := authContext.UnmappedIdentity.(LocalUser)
	return ok
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
	actionVerbs := []string{}
	if req.ResourceType == types.KindNode {
		actionVerbs = append(actionVerbs, types.VerbList)
	} else {
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

func (a *ServerWithRoles) Close() error {
	return a.authServer.Close()
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
