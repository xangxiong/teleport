/*
Copyright 2018-2019 Gravitational, Inc.

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

package cache

import (
	"context"
	"fmt"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"

	"github.com/gravitational/trace"
)

// collection is responsible for managing collection
// of resources updates
type collection interface {
	// fetch fetches resources and returns a function which
	// will apply said resources to the cache.  fetch *must*
	// not mutate cache state outside of the apply function.
	fetch(ctx context.Context) (apply func(ctx context.Context) error, err error)
	// processEvent processes event
	processEvent(ctx context.Context, e types.Event) error
	// watchKind returns a watch
	// required for this collection
	watchKind() types.WatchKind
}

// setupCollections returns a mapping of collections
func setupCollections(c *Cache, watches []types.WatchKind) (map[resourceKind]collection, error) {
	collections := make(map[resourceKind]collection, len(watches))
	for _, watch := range watches {
		resourceKind := resourceKindFromWatchKind(watch)
		switch watch.Kind {
		case types.KindCertAuthority:
			if c.Trust == nil {
				return nil, trace.BadParameter("missing parameter Trust")
			}
			var filter types.CertAuthorityFilter
			filter.FromMap(watch.Filter)
			collections[resourceKind] = &certAuthority{Cache: c, watch: watch, filter: filter}
		case types.KindToken:
			if c.Provisioner == nil {
				return nil, trace.BadParameter("missing parameter Provisioner")
			}
			collections[resourceKind] = &provisionToken{watch: watch, Cache: c}
		case types.KindClusterAuditConfig:
			if c.ClusterConfig == nil {
				return nil, trace.BadParameter("missing parameter ClusterConfig")
			}
			collections[resourceKind] = &clusterAuditConfig{watch: watch, Cache: c}
		case types.KindClusterNetworkingConfig:
			if c.ClusterConfig == nil {
				return nil, trace.BadParameter("missing parameter ClusterConfig")
			}
			collections[resourceKind] = &clusterNetworkingConfig{watch: watch, Cache: c}
		case types.KindClusterAuthPreference:
			if c.ClusterConfig == nil {
				return nil, trace.BadParameter("missing parameter ClusterConfig")
			}
			collections[resourceKind] = &authPreference{watch: watch, Cache: c}
		case types.KindSessionRecordingConfig:
			if c.ClusterConfig == nil {
				return nil, trace.BadParameter("missing parameter ClusterConfig")
			}
			collections[resourceKind] = &sessionRecordingConfig{watch: watch, Cache: c}
		case types.KindRole:
			if c.Access == nil {
				return nil, trace.BadParameter("missing parameter Access")
			}
			collections[resourceKind] = &role{watch: watch, Cache: c}
		case types.KindNamespace:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &namespace{watch: watch, Cache: c}
		case types.KindNode:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &node{watch: watch, Cache: c}
		case types.KindProxy:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &proxy{watch: watch, Cache: c}
		case types.KindAuthServer:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &authServer{watch: watch, Cache: c}
		case types.KindReverseTunnel:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &reverseTunnel{watch: watch, Cache: c}
		case types.KindTunnelConnection:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &tunnelConnection{watch: watch, Cache: c}
		case types.KindAccessRequest:
			if c.DynamicAccess == nil {
				return nil, trace.BadParameter("missing parameter DynamicAccess")
			}
			collections[resourceKind] = &accessRequest{watch: watch, Cache: c}
		case types.KindWebSession:
			switch watch.SubKind {
			case types.KindWebSession:
				if c.WebSession == nil {
					return nil, trace.BadParameter("missing parameter WebSession")
				}
				collections[resourceKind] = &webSession{watch: watch, Cache: c}
			}
		case types.KindWebToken:
			if c.WebToken == nil {
				return nil, trace.BadParameter("missing parameter WebToken")
			}
			collections[resourceKind] = &webToken{watch: watch, Cache: c}
		case types.KindNetworkRestrictions:
			if c.Restrictions == nil {
				return nil, trace.BadParameter("missing parameter Restrictions")
			}
			collections[resourceKind] = &networkRestrictions{watch: watch, Cache: c}
		case types.KindLock:
			if c.Access == nil {
				return nil, trace.BadParameter("missing parameter Access")
			}
			collections[resourceKind] = &lock{watch: watch, Cache: c}
		default:
			return nil, trace.BadParameter("resource %q is not supported", watch.Kind)
		}
	}
	return collections, nil
}

func resourceKindFromWatchKind(wk types.WatchKind) resourceKind {
	switch wk.Kind {
	case types.KindWebSession:
		// Web sessions use subkind to differentiate between
		// the types of sessions
		return resourceKind{
			kind:    wk.Kind,
			subkind: wk.SubKind,
			version: wk.Version,
		}
	}
	return resourceKind{
		kind:    wk.Kind,
		version: wk.Version,
	}
}

func resourceKindFromResource(res types.Resource) resourceKind {
	switch res.GetKind() {
	case types.KindWebSession:
		// Web sessions use subkind to differentiate between
		// the types of sessions
		return resourceKind{
			kind:    res.GetKind(),
			subkind: res.GetSubKind(),
		}
	case types.KindAppServer:
		// DELETE IN 9.0.
		switch res.GetVersion() {
		case types.V2:
			return resourceKind{
				kind:    res.GetKind(),
				version: res.GetVersion(),
			}
		}
	}
	return resourceKind{
		kind: res.GetKind(),
	}
}

type resourceKind struct {
	kind    string
	subkind string
	version string
}

func (r resourceKind) String() string {
	if r.subkind == "" {
		return r.kind
	}
	return fmt.Sprintf("%s/%s", r.kind, r.subkind)
}

type accessRequest struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (r *accessRequest) erase(ctx context.Context) error {
	if err := r.dynamicAccessCache.DeleteAllAccessRequests(ctx); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (r *accessRequest) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := r.DynamicAccess.GetAccessRequests(ctx, types.AccessRequestFilter{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := r.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := r.dynamicAccessCache.UpsertAccessRequest(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (r *accessRequest) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := r.dynamicAccessCache.DeleteAccessRequest(ctx, event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				r.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(*types.AccessRequestV3)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := r.dynamicAccessCache.UpsertAccessRequest(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		r.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (r *accessRequest) watchKind() types.WatchKind {
	return r.watch
}

type tunnelConnection struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *tunnelConnection) erase(ctx context.Context) error {
	if err := c.presenceCache.DeleteAllTunnelConnections(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *tunnelConnection) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Presence.GetAllTunnelConnections()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := c.presenceCache.UpsertTunnelConnection(resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *tunnelConnection) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.presenceCache.DeleteTunnelConnection(event.Resource.GetSubKind(), event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.TunnelConnection)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.presenceCache.UpsertTunnelConnection(resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *tunnelConnection) watchKind() types.WatchKind {
	return c.watch
}

type reverseTunnel struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *reverseTunnel) erase(ctx context.Context) error {
	if err := c.presenceCache.DeleteAllReverseTunnels(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *reverseTunnel) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Presence.GetReverseTunnels(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := c.presenceCache.UpsertReverseTunnel(resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *reverseTunnel) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.presenceCache.DeleteReverseTunnel(event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.ReverseTunnel)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.presenceCache.UpsertReverseTunnel(resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *reverseTunnel) watchKind() types.WatchKind {
	return c.watch
}

type proxy struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *proxy) erase(ctx context.Context) error {
	if err := c.presenceCache.DeleteAllProxies(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *proxy) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Presence.GetProxies()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}

		for _, resource := range resources {
			if err := c.presenceCache.UpsertProxy(resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *proxy) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.presenceCache.DeleteProxy(event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.Server)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.presenceCache.UpsertProxy(resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *proxy) watchKind() types.WatchKind {
	return c.watch
}

type authServer struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *authServer) erase(ctx context.Context) error {
	if err := c.presenceCache.DeleteAllAuthServers(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *authServer) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Presence.GetAuthServers()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}

		for _, resource := range resources {
			if err := c.presenceCache.UpsertAuthServer(resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *authServer) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.presenceCache.DeleteAuthServer(event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.Server)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.presenceCache.UpsertAuthServer(resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *authServer) watchKind() types.WatchKind {
	return c.watch
}

type node struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *node) erase(ctx context.Context) error {
	if err := c.presenceCache.DeleteAllNodes(ctx, apidefaults.Namespace); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *node) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Presence.GetNodes(ctx, apidefaults.Namespace)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if _, err := c.presenceCache.UpsertNode(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *node) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.presenceCache.DeleteNode(ctx, event.Resource.GetMetadata().Namespace, event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.Server)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if _, err := c.presenceCache.UpsertNode(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *node) watchKind() types.WatchKind {
	return c.watch
}

type namespace struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *namespace) erase(ctx context.Context) error {
	if err := c.presenceCache.DeleteAllNamespaces(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *namespace) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Presence.GetNamespaces()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := c.presenceCache.UpsertNamespace(resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *namespace) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.presenceCache.DeleteNamespace(event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete namespace %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(*types.Namespace)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.presenceCache.UpsertNamespace(*resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *namespace) watchKind() types.WatchKind {
	return c.watch
}

type certAuthority struct {
	*Cache
	watch types.WatchKind
	// filter extracted from watch.Filter, to avoid rebuilding it on every event
	filter types.CertAuthorityFilter
}

func (c *certAuthority) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	applyHostCAs, err := c.fetchCertAuthorities(ctx, types.HostCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	applyUserCAs, err := c.fetchCertAuthorities(ctx, types.UserCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// DELETE IN 11.0.
	// missingDatabaseCA is needed only when leaf cluster v9 is connected
	// to root cluster v10. Database CA has been added in v10, so older
	// clusters don't have it and fetchCertAuthorities() returns an error.
	missingDatabaseCA := false
	applyDatabaseCAs, err := c.fetchCertAuthorities(ctx, types.DatabaseCA)
	if trace.IsBadParameter(err) {
		missingDatabaseCA = true
	} else if err != nil {
		return nil, trace.Wrap(err)
	}

	applyJWTSigners, err := c.fetchCertAuthorities(ctx, types.JWTSigner)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return func(ctx context.Context) error {
		if err := applyHostCAs(ctx); err != nil {
			return trace.Wrap(err)
		}
		if err := applyUserCAs(ctx); err != nil {
			return trace.Wrap(err)
		}
		if !missingDatabaseCA {
			if err := applyDatabaseCAs(ctx); err != nil {
				return trace.Wrap(err)
			}
		} else {
			if err := c.trustCache.DeleteAllCertAuthorities(types.DatabaseCA); err != nil {
				if !trace.IsNotFound(err) {
					return trace.Wrap(err)
				}
			}
		}
		return trace.Wrap(applyJWTSigners(ctx))
	}, nil
}

func (c *certAuthority) fetchCertAuthorities(ctx context.Context, caType types.CertAuthType) (apply func(ctx context.Context) error, err error) {
	authorities, err := c.Trust.GetCertAuthorities(ctx, caType, c.watch.LoadSecrets)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// this can be removed once we get the ability to fetch CAs with a filter,
	// but it should be harmless, and it could be kept as additional safety
	if !c.filter.IsEmpty() {
		filteredCAs := make([]types.CertAuthority, 0, len(authorities))
		for _, ca := range authorities {
			if c.filter.Match(ca) {
				filteredCAs = append(filteredCAs, ca)
			}
		}
		authorities = filteredCAs
	}

	return func(ctx context.Context) error {
		if err := c.trustCache.DeleteAllCertAuthorities(caType); err != nil {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
		}
		for _, resource := range authorities {
			if err := c.trustCache.UpsertCertAuthority(resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *certAuthority) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.trustCache.DeleteCertAuthority(types.CertAuthID{
			Type:       types.CertAuthType(event.Resource.GetSubKind()),
			DomainName: event.Resource.GetName(),
		})
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete cert authority %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.CertAuthority)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if !c.filter.Match(resource) {
			return nil
		}
		if err := c.trustCache.UpsertCertAuthority(resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *certAuthority) watchKind() types.WatchKind {
	return c.watch
}

type provisionToken struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *provisionToken) erase(ctx context.Context) error {
	if err := c.provisionerCache.DeleteAllTokens(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *provisionToken) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	tokens, err := c.Provisioner.GetTokens(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range tokens {
			if err := c.provisionerCache.UpsertToken(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *provisionToken) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.provisionerCache.DeleteToken(ctx, event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete provisioning token %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.ProvisionToken)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.provisionerCache.UpsertToken(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *provisionToken) watchKind() types.WatchKind {
	return c.watch
}

type role struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *role) erase(ctx context.Context) error {
	if err := c.accessCache.DeleteAllRoles(); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *role) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Access.GetRoles(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := c.accessCache.UpsertRole(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *role) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.accessCache.DeleteRole(ctx, event.Resource.GetName())
		if err != nil {
			// resource could be missing in the cache
			// expired or not created, if the first consumed
			// event is delete
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete role %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.Role)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.accessCache.UpsertRole(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *role) watchKind() types.WatchKind {
	return c.watch
}

type webSession struct {
	*Cache
	watch types.WatchKind
}

func (r *webSession) erase(ctx context.Context) error {
	err := r.webSessionCache.DeleteAll(ctx)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	return nil
}

func (r *webSession) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := r.WebSession.List(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := r.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := r.webSessionCache.Upsert(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (r *webSession) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := r.webSessionCache.Delete(ctx, types.DeleteWebSessionRequest{
			SessionID: event.Resource.GetName(),
		})
		if err != nil {
			// Resource could be missing in the cache expired or not created, if the
			// first consumed event is delete.
			if !trace.IsNotFound(err) {
				r.WithError(err).Warn("Failed to delete resource.")
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.WebSession)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := r.webSessionCache.Upsert(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		r.WithField("event", event.Type).Warn("Skipping unsupported event type.")
	}
	return nil
}

func (r *webSession) watchKind() types.WatchKind {
	return r.watch
}

type webToken struct {
	*Cache
	watch types.WatchKind
}

func (r *webToken) erase(ctx context.Context) error {
	err := r.webTokenCache.DeleteAll(ctx)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	return nil
}

func (r *webToken) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := r.WebToken.List(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := r.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := r.webTokenCache.Upsert(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (r *webToken) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := r.webTokenCache.Delete(ctx, types.DeleteWebTokenRequest{
			Token: event.Resource.GetName(),
		})
		if err != nil {
			// Resource could be missing in the cache expired or not created, if the
			// first consumed event is delete.
			if !trace.IsNotFound(err) {
				r.WithError(err).Warn("Failed to delete resource.")
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.WebToken)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := r.webTokenCache.Upsert(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		r.WithField("event", event.Type).Warn("Skipping unsupported event type.")
	}
	return nil
}

func (r *webToken) watchKind() types.WatchKind {
	return r.watch
}

type authPreference struct {
	*Cache
	watch types.WatchKind
}

func (c *authPreference) erase(ctx context.Context) error {
	if err := c.clusterConfigCache.DeleteAuthPreference(ctx); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *authPreference) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	var noConfig bool
	resource, err := c.ClusterConfig.GetAuthPreference(ctx)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		noConfig = true
	}
	return func(ctx context.Context) error {
		// either zero or one instance exists, so we either erase or
		// update, but not both.
		if noConfig {
			if err := c.erase(ctx); err != nil {
				return trace.Wrap(err)
			}
			return nil
		}

		if err := c.clusterConfigCache.SetAuthPreference(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
		return nil
	}, nil
}

func (c *authPreference) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.clusterConfigCache.DeleteAuthPreference(ctx)
		if err != nil {
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.AuthPreference)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.clusterConfigCache.SetAuthPreference(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *authPreference) watchKind() types.WatchKind {
	return c.watch
}

type clusterAuditConfig struct {
	*Cache
	watch types.WatchKind
}

func (c *clusterAuditConfig) erase(ctx context.Context) error {
	if err := c.clusterConfigCache.DeleteClusterAuditConfig(ctx); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *clusterAuditConfig) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	var noConfig bool
	resource, err := c.ClusterConfig.GetClusterAuditConfig(ctx)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		noConfig = true
	}
	return func(ctx context.Context) error {
		// either zero or one instance exists, so we either erase or
		// update, but not both.
		if noConfig {
			if err := c.erase(ctx); err != nil {
				return trace.Wrap(err)
			}
			return nil
		}

		if err := c.clusterConfigCache.SetClusterAuditConfig(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
		return nil
	}, nil
}

func (c *clusterAuditConfig) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.clusterConfigCache.DeleteClusterAuditConfig(ctx)
		if err != nil {
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.ClusterAuditConfig)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.clusterConfigCache.SetClusterAuditConfig(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *clusterAuditConfig) watchKind() types.WatchKind {
	return c.watch
}

type clusterNetworkingConfig struct {
	*Cache
	watch types.WatchKind
}

func (c *clusterNetworkingConfig) erase(ctx context.Context) error {
	if err := c.clusterConfigCache.DeleteClusterNetworkingConfig(ctx); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *clusterNetworkingConfig) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	var noConfig bool
	resource, err := c.ClusterConfig.GetClusterNetworkingConfig(ctx)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		noConfig = true
	}
	return func(ctx context.Context) error {
		// either zero or one instance exists, so we either erase or
		// update, but not both.
		if noConfig {
			if err := c.erase(ctx); err != nil {
				return trace.Wrap(err)
			}
			return nil
		}

		if err := c.clusterConfigCache.SetClusterNetworkingConfig(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
		return nil
	}, nil
}

func (c *clusterNetworkingConfig) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.clusterConfigCache.DeleteClusterNetworkingConfig(ctx)
		if err != nil {
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.ClusterNetworkingConfig)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.clusterConfigCache.SetClusterNetworkingConfig(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *clusterNetworkingConfig) watchKind() types.WatchKind {
	return c.watch
}

type sessionRecordingConfig struct {
	*Cache
	watch types.WatchKind
}

func (c *sessionRecordingConfig) erase(ctx context.Context) error {
	if err := c.clusterConfigCache.DeleteSessionRecordingConfig(ctx); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *sessionRecordingConfig) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	var noConfig bool
	resource, err := c.ClusterConfig.GetSessionRecordingConfig(ctx)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		noConfig = true
	}
	return func(ctx context.Context) error {
		// either zero or one instance exists, so we either erase or
		// update, but not both.
		if noConfig {
			if err := c.erase(ctx); err != nil {
				return trace.Wrap(err)
			}
			return nil
		}

		if err := c.clusterConfigCache.SetSessionRecordingConfig(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
		return nil
	}, nil
}

func (c *sessionRecordingConfig) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.clusterConfigCache.DeleteSessionRecordingConfig(ctx)
		if err != nil {
			if !trace.IsNotFound(err) {
				c.Warningf("Failed to delete resource %v.", err)
				return trace.Wrap(err)
			}
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.SessionRecordingConfig)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.clusterConfigCache.SetSessionRecordingConfig(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warningf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *sessionRecordingConfig) watchKind() types.WatchKind {
	return c.watch
}

type networkRestrictions struct {
	*Cache
	watch types.WatchKind
}

func (r *networkRestrictions) erase(ctx context.Context) error {
	if err := r.restrictionsCache.DeleteNetworkRestrictions(ctx); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (r *networkRestrictions) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	nr, err := r.Restrictions.GetNetworkRestrictions(ctx)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		nr = nil
	}
	return func(ctx context.Context) error {
		if nr == nil {
			if err := r.erase(ctx); err != nil {
				return trace.Wrap(err)
			}
			return nil
		}
		return trace.Wrap(r.restrictionsCache.SetNetworkRestrictions(ctx, nr))
	}, nil
}

func (r *networkRestrictions) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		return trace.Wrap(r.restrictionsCache.DeleteNetworkRestrictions(ctx))
	case types.OpPut:
		resource, ok := event.Resource.(types.NetworkRestrictions)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		return trace.Wrap(r.restrictionsCache.SetNetworkRestrictions(ctx, resource))
	default:
		r.Warnf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (r *networkRestrictions) watchKind() types.WatchKind {
	return r.watch
}

type lock struct {
	*Cache
	watch types.WatchKind
}

func (c *lock) erase(ctx context.Context) error {
	err := c.accessCache.DeleteAllLocks(ctx)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	return nil
}

func (c *lock) fetch(ctx context.Context) (apply func(ctx context.Context) error, err error) {
	resources, err := c.Access.GetLocks(ctx, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return func(ctx context.Context) error {
		if err := c.erase(ctx); err != nil {
			return trace.Wrap(err)
		}
		for _, resource := range resources {
			if err := c.accessCache.UpsertLock(ctx, resource); err != nil {
				return trace.Wrap(err)
			}
		}
		return nil
	}, nil
}

func (c *lock) processEvent(ctx context.Context, event types.Event) error {
	switch event.Type {
	case types.OpDelete:
		err := c.accessCache.DeleteLock(ctx, event.Resource.GetName())
		if err != nil && !trace.IsNotFound(err) {
			c.Warningf("Failed to delete resource %v.", err)
			return trace.Wrap(err)
		}
	case types.OpPut:
		resource, ok := event.Resource.(types.Lock)
		if !ok {
			return trace.BadParameter("unexpected type %T", event.Resource)
		}
		if err := c.accessCache.UpsertLock(ctx, resource); err != nil {
			return trace.Wrap(err)
		}
	default:
		c.Warnf("Skipping unsupported event type %v.", event.Type)
	}
	return nil
}

func (c *lock) watchKind() types.WatchKind {
	return c.watch
}
