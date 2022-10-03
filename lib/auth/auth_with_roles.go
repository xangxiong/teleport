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
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
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

func (a *ServerWithRoles) GetDomainName(ctx context.Context) (string, error) {
	// anyone can read it, no harm in that
	return a.authServer.GetDomainName()
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
