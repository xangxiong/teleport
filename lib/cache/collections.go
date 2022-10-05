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
		case types.KindProxy:
			if c.Presence == nil {
				return nil, trace.BadParameter("missing parameter Presence")
			}
			collections[resourceKind] = &proxy{watch: watch, Cache: c}
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

type proxy struct {
	*Cache
	watch types.WatchKind
}

// erase erases all data in the collection
func (c *proxy) erase(ctx context.Context) error {
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
