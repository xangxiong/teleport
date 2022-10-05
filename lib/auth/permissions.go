/*
Copyright 2015-2018 Gravitational, Inc.

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

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/gravitational/trace"
	"github.com/vulcand/predicate/builder"
)

// AuthorizerAccessPoint is the access point contract required by an Authorizer
type AuthorizerAccessPoint interface {
	// GetAuthPreference returns the cluster authentication configuration.
	GetAuthPreference(ctx context.Context) (types.AuthPreference, error)

	// GetRole returns role by name
	GetRole(ctx context.Context, name string) (types.Role, error)

	// GetUser returns a services.User for this cluster.
	GetUser(name string, withSecrets bool) (types.User, error)

	// GetCertAuthority returns cert authority by id
	GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool, opts ...services.MarshalOption) (types.CertAuthority, error)

	// GetCertAuthorities returns a list of cert authorities
	GetCertAuthorities(ctx context.Context, caType types.CertAuthType, loadKeys bool, opts ...services.MarshalOption) ([]types.CertAuthority, error)

	// GetClusterNetworkingConfig returns cluster networking configuration.
	GetClusterNetworkingConfig(ctx context.Context, opts ...services.MarshalOption) (types.ClusterNetworkingConfig, error)

	// GetSessionRecordingConfig returns session recording configuration.
	GetSessionRecordingConfig(ctx context.Context, opts ...services.MarshalOption) (types.SessionRecordingConfig, error)
}

// Context is authorization context
type Context struct {
	// User is the username
	User types.User
	// Checker is access checker
	Checker services.AccessChecker
	// Identity holds the caller identity:
	// 1. If caller is a user
	//   a. local user identity
	//   b. remote user identity remapped to local identity based on trusted
	//      cluster role mapping.
	// 2. If caller is a teleport instance, Identity holds their identity as-is
	//    (because there's no role mapping for non-human roles)
	Identity IdentityGetter
	// UnmappedIdentity holds the original caller identity. If this is a remote
	// user, UnmappedIdentity holds the data before role mapping. Otherwise,
	// it's identical to Identity.
	UnmappedIdentity IdentityGetter
}

// LockTargets returns a list of LockTargets inferred from the context's
// Identity and UnmappedIdentity.
func (c *Context) LockTargets() []types.LockTarget {
	lockTargets := services.LockTargetsFromTLSIdentity(c.Identity.GetIdentity())
Loop:
	for _, unmappedTarget := range services.LockTargetsFromTLSIdentity(c.UnmappedIdentity.GetIdentity()) {
		// Append a lock target from UnmappedIdentity only if it is not already
		// known from Identity.
		for _, knownTarget := range lockTargets {
			if unmappedTarget.Equals(knownTarget) {
				continue Loop
			}
		}
		lockTargets = append(lockTargets, unmappedTarget)
	}
	if r, ok := c.Identity.(BuiltinRole); ok && r.Role == types.RoleNode {
		lockTargets = append(lockTargets,
			types.LockTarget{Node: r.GetServerID()},
			types.LockTarget{Node: r.Identity.Username})
	}
	return lockTargets
}

func roleSpecForProxyWithRecordAtProxy(clusterName string) types.RoleSpecV5 {
	base := roleSpecForProxy(clusterName)
	base.Allow.Rules = append(base.Allow.Rules, types.NewRule(types.KindHostCert, services.RW()))
	return base
}

func roleSpecForProxy(clusterName string) types.RoleSpecV5 {
	return types.RoleSpecV5{
		Allow: types.RoleConditions{
			Namespaces:     []string{types.Wildcard},
			ClusterLabels:  types.Labels{types.Wildcard: []string{types.Wildcard}},
			NodeLabels:     types.Labels{types.Wildcard: []string{types.Wildcard}},
			AppLabels:      types.Labels{types.Wildcard: []string{types.Wildcard}},
			DatabaseLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
			Rules: []types.Rule{
				types.NewRule(types.KindProxy, services.RW()),
				types.NewRule(types.KindSSHSession, services.RW()),
				types.NewRule(types.KindSession, services.RO()),
				types.NewRule(types.KindEvent, services.RW()),
				types.NewRule(types.KindNamespace, services.RO()),
				types.NewRule(types.KindNode, services.RO()),
				types.NewRule(types.KindAuthServer, services.RO()),
				types.NewRule(types.KindReverseTunnel, services.RO()),
				types.NewRule(types.KindCertAuthority, services.ReadNoSecrets()),
				types.NewRule(types.KindUser, services.RO()),
				types.NewRule(types.KindRole, services.RO()),
				types.NewRule(types.KindClusterAuthPreference, services.RO()),
				types.NewRule(types.KindClusterName, services.RO()),
				types.NewRule(types.KindClusterAuditConfig, services.RO()),
				types.NewRule(types.KindClusterNetworkingConfig, services.RO()),
				types.NewRule(types.KindSessionRecordingConfig, services.RO()),
				types.NewRule(types.KindStaticTokens, services.RO()),
				types.NewRule(types.KindTunnelConnection, services.RW()),
				types.NewRule(types.KindRemoteCluster, services.RO()),
				types.NewRule(types.KindSemaphore, services.RW()),
				types.NewRule(types.KindLock, services.RO()),
				types.NewRule(types.KindToken, []string{types.VerbRead, types.VerbDelete}),
				// this rule allows local proxy to update the remote cluster's host certificate authorities
				// during certificates renewal
				{
					Resources: []string{types.KindCertAuthority},
					Verbs:     []string{types.VerbCreate, types.VerbRead, types.VerbUpdate},
					// allow administrative access to the host certificate authorities
					// matching any cluster name except local
					Where: builder.And(
						builder.Equals(services.CertAuthorityTypeExpr, builder.String(string(types.HostCA))),
						builder.Not(
							builder.Equals(
								services.ResourceNameExpr,
								builder.String(clusterName),
							),
						),
					).String(),
				},
			},
		},
	}
}

// RoleSetForBuiltinRole returns RoleSet for embedded builtin role
func RoleSetForBuiltinRoles(clusterName string, recConfig types.SessionRecordingConfig, roles ...types.SystemRole) (services.RoleSet, error) {
	var definitions []types.Role
	for _, role := range roles {
		rd, err := definitionForBuiltinRole(clusterName, recConfig, role)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		definitions = append(definitions, rd)
	}
	return services.NewRoleSet(definitions...), nil
}

// definitionForBuiltinRole constructs the appropriate role definition for a given builtin role.
func definitionForBuiltinRole(clusterName string, recConfig types.SessionRecordingConfig, role types.SystemRole) (types.Role, error) {
	switch role {
	case types.RoleAuth:
		return services.RoleFromSpec(
			role.String(),
			types.RoleSpecV5{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindAuthServer, services.RW()),
					},
				},
			})
	case types.RoleProvisionToken:
		return services.RoleFromSpec(role.String(), types.RoleSpecV5{})
	case types.RoleNode:
		return services.RoleFromSpec(
			role.String(),
			types.RoleSpecV5{
				Allow: types.RoleConditions{
					Namespaces: []string{types.Wildcard},
					Rules: []types.Rule{
						types.NewRule(types.KindNode, services.RW()),
						types.NewRule(types.KindSSHSession, services.RW()),
						types.NewRule(types.KindSession, services.RO()),
						types.NewRule(types.KindEvent, services.RW()),
						types.NewRule(types.KindProxy, services.RO()),
						types.NewRule(types.KindCertAuthority, services.ReadNoSecrets()),
						types.NewRule(types.KindUser, services.RO()),
						types.NewRule(types.KindNamespace, services.RO()),
						types.NewRule(types.KindRole, services.RO()),
						types.NewRule(types.KindAuthServer, services.RO()),
						types.NewRule(types.KindReverseTunnel, services.RW()),
						types.NewRule(types.KindTunnelConnection, services.RO()),
						types.NewRule(types.KindClusterName, services.RO()),
						types.NewRule(types.KindClusterAuditConfig, services.RO()),
						types.NewRule(types.KindClusterNetworkingConfig, services.RO()),
						types.NewRule(types.KindSessionRecordingConfig, services.RO()),
						types.NewRule(types.KindClusterAuthPreference, services.RO()),
						types.NewRule(types.KindSemaphore, services.RW()),
						types.NewRule(types.KindLock, services.RO()),
						types.NewRule(types.KindNetworkRestrictions, services.RO()),
					},
				},
			})
	case types.RoleProxy:
		// if in recording mode, return a different set of permissions than regular
		// mode. recording proxy needs to be able to generate host certificates.
		if services.IsRecordAtProxy(recConfig.GetMode()) {
			return services.RoleFromSpec(
				role.String(),
				roleSpecForProxyWithRecordAtProxy(clusterName),
			)
		}
		return services.RoleFromSpec(
			role.String(),
			roleSpecForProxy(clusterName),
		)
	case types.RoleAdmin:
		return services.RoleFromSpec(
			role.String(),
			types.RoleSpecV5{
				Options: types.RoleOptions{
					MaxSessionTTL: types.MaxDuration(),
				},
				Allow: types.RoleConditions{
					Namespaces:    []string{types.Wildcard},
					Logins:        []string{},
					NodeLabels:    types.Labels{types.Wildcard: []string{types.Wildcard}},
					ClusterLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
					Rules: []types.Rule{
						types.NewRule(types.Wildcard, services.RW()),
					},
				},
			})
	case types.RoleNop:
		return services.RoleFromSpec(
			role.String(),
			types.RoleSpecV5{
				Allow: types.RoleConditions{
					Namespaces: []string{},
					Rules:      []types.Rule{},
				},
			})
	}

	return nil, trace.NotFound("builtin role %q is not recognized", role.String())
}

type contextKey string

const (
	// ContextUser is a user set in the context of the request
	ContextUser contextKey = "teleport-user"
	// ContextClientAddr is a client address set in the context of the request
	ContextClientAddr contextKey = "client-addr"
)

// WithDelegator alias for backwards compatibility
var WithDelegator = utils.WithDelegator

// ClientUsername returns the username of a remote HTTP client making the call.
// If ctx didn't pass through auth middleware or did not come from an HTTP
// request, teleport.UserSystem is returned.
func ClientUsername(ctx context.Context) string {
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return teleport.UserSystem
	}
	identity := userWithIdentity.GetIdentity()
	if identity.Username == "" {
		return teleport.UserSystem
	}
	return identity.Username
}

// GetClientUsername returns the username of a remote HTTP client making the call.
// If ctx didn't pass through auth middleware or did not come from an HTTP
// request, returns an error.
func GetClientUsername(ctx context.Context) (string, error) {
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return "", trace.AccessDenied("missing identity")
	}
	identity := userWithIdentity.GetIdentity()
	if identity.Username == "" {
		return "", trace.AccessDenied("missing identity username")
	}
	return identity.Username, nil
}

// ClientImpersonator returns the impersonator username of a remote client
// making the call. If not present, returns an empty string
func ClientImpersonator(ctx context.Context) string {
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return ""
	}
	identity := userWithIdentity.GetIdentity()
	return identity.Impersonator
}

// ClientUserMetadata returns a UserMetadata suitable for events caused by a
// remote client making a call. If ctx didn't pass through auth middleware or
// did not come from an HTTP request, metadata for teleport.UserSystem is
// returned.
func ClientUserMetadata(ctx context.Context) apievents.UserMetadata {
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return apievents.UserMetadata{
			User: teleport.UserSystem,
		}
	}
	meta := userWithIdentity.GetIdentity().GetUserMetadata()
	if meta.User == "" {
		meta.User = teleport.UserSystem
	}
	return meta
}

// ClientUserMetadataWithUser returns a UserMetadata suitable for events caused
// by a remote client making a call, with the specified username overriding the one
// from the remote client.
func ClientUserMetadataWithUser(ctx context.Context, user string) apievents.UserMetadata {
	userI := ctx.Value(ContextUser)
	userWithIdentity, ok := userI.(IdentityGetter)
	if !ok {
		return apievents.UserMetadata{
			User: user,
		}
	}
	meta := userWithIdentity.GetIdentity().GetUserMetadata()
	meta.User = user
	return meta
}

// LocalUser is a local user
type LocalUser struct {
	// Username is local username
	Username string
	// Identity is x509-derived identity used to build this user
	Identity tlsca.Identity
}

// GetIdentity returns client identity
func (l LocalUser) GetIdentity() tlsca.Identity {
	return l.Identity
}

// IdentityGetter returns the unmapped client identity.
//
// Unmapped means that if the client is a remote cluster user, the returned
// tlsca.Identity contains data from the remote cluster before role mapping is
// applied.
type IdentityGetter interface {
	// GetIdentity  returns x509-derived identity of the user
	GetIdentity() tlsca.Identity
}

// WrapIdentity wraps identity to return identity getter function
type WrapIdentity tlsca.Identity

// GetIdentity returns identity
func (i WrapIdentity) GetIdentity() tlsca.Identity {
	return tlsca.Identity(i)
}

// BuiltinRole is the role of the Teleport service.
type BuiltinRole struct {
	// Role is the primary builtin role this username is associated with
	Role types.SystemRole

	// AdditionalSystemRoles is a collection of additional system roles held by
	// this identity (only currently used by identities with RoleInstance as their
	// primary role).
	AdditionalSystemRoles types.SystemRoles

	// Username is for authentication tracking purposes
	Username string

	// ClusterName is the name of the local cluster
	ClusterName string

	// Identity is source x509 used to build this role
	Identity tlsca.Identity
}

// IsServer returns true if the primary role is either RoleInstance, or one of
// the local service roles (e.g. proxy).
func (r BuiltinRole) IsServer() bool {
	return r.Role == types.RoleInstance || r.Role.IsLocalService()
}

// GetServerID extracts the identity from the full name. The username
// extracted from the node's identity (x.509 certificate) is expected to
// consist of "<server-id>.<cluster-name>" so strip the cluster name suffix
// to get the server id.
//
// Note that as of right now Teleport expects server id to be a UUID4 but
// older Gravity clusters used to override it with strings like
// "192_168_1_1.<cluster-name>" so this code can't rely on it being
// UUID4 to account for clusters upgraded from older versions.
func (r BuiltinRole) GetServerID() string {
	return strings.TrimSuffix(r.Identity.Username, "."+r.ClusterName)
}

// GetIdentity returns client identity
func (r BuiltinRole) GetIdentity() tlsca.Identity {
	return r.Identity
}

// RemoteBuiltinRole is the role of the remote (service connecting via trusted cluster link)
// Teleport service.
type RemoteBuiltinRole struct {
	// Role is the builtin role of the user
	Role types.SystemRole

	// Username is for authentication tracking purposes
	Username string

	// ClusterName is the name of the remote cluster.
	ClusterName string

	// Identity is source x509 used to build this role
	Identity tlsca.Identity
}

// GetIdentity returns client identity
func (r RemoteBuiltinRole) GetIdentity() tlsca.Identity {
	return r.Identity
}

// RemoteUser defines encoded remote user.
type RemoteUser struct {
	// Username is a name of the remote user
	Username string `json:"username"`

	// ClusterName is the name of the remote cluster
	// of the user.
	ClusterName string `json:"cluster_name"`

	// RemoteRoles is optional list of remote roles
	RemoteRoles []string `json:"remote_roles"`

	// Principals is a list of Unix logins.
	Principals []string `json:"principals"`

	// Identity is source x509 used to build this role
	Identity tlsca.Identity
}

// GetIdentity returns client identity
func (r RemoteUser) GetIdentity() tlsca.Identity {
	return r.Identity
}
