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
	"sync"
	"time"

	"github.com/gravitational/teleport"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/atomic"
)

// ForNode sets up watch configuration for node
func ForNode(cfg Config) Config {
	var caFilter map[string]string
	if cfg.ClusterConfig != nil {
		clusterName, err := cfg.ClusterConfig.GetClusterName()
		if err == nil {
			caFilter = types.CertAuthorityFilter{
				types.HostCA: clusterName.GetClusterName(),
				types.UserCA: types.Wildcard,
			}.IntoMap()
		}
	}
	cfg.target = "node"
	cfg.Watches = []types.WatchKind{
		{Kind: types.KindCertAuthority, Filter: caFilter},
		{Kind: types.KindClusterName},
		{Kind: types.KindClusterAuditConfig},
		{Kind: types.KindClusterNetworkingConfig},
		{Kind: types.KindClusterAuthPreference},
		{Kind: types.KindSessionRecordingConfig},
		{Kind: types.KindRole},
		// Node only needs to "know" about default
		// namespace events to avoid matching too much
		// data about other namespaces or node events
		{Kind: types.KindNamespace, Name: apidefaults.Namespace},
		{Kind: types.KindNetworkRestrictions},
	}
	cfg.QueueSize = defaults.NodeQueueSize
	return cfg
}

// SetupConfigFn is a function that sets up configuration
// for cache
type SetupConfigFn func(c Config) Config

// Cache implements auth.Cache interface and remembers
// the previously returned upstream value for each API call.
//
// This which can be used if the upstream AccessPoint goes offline
type Cache struct {
	Config

	// Entry is a logging entry
	*log.Entry

	// rw is used to prevent reads of invalid cache states.  From a
	// memory-safety perspective, this RWMutex is just used to protect
	// the `ok` field.  *However*, cache reads must hold the read lock
	// for the duration of the read, not just when checking the `ok`
	// field.  Since the write lock must be held in order to modify
	// the `ok` field, this serves to ensure that all in-progress reads
	// complete *before* a reset can begin.
	rw sync.RWMutex
	// ok indicates whether the cache is in a valid state for reads.
	// If `ok` is `false`, reads are forwarded directly to the backend.
	ok bool

	// generation is a counter that is incremented each time a healthy
	// state is established.  A generation of zero means that a healthy
	// state was never established.  Note that a generation of zero does
	// not preclude `ok` being true in the case that we have loaded a
	// previously healthy state from the backend.
	generation *atomic.Uint64

	// initC is closed on the first attempt to initialize the
	// cache, whether or not it is successful.  Once initC
	// has returned, initErr is safe to read.
	initC chan struct{}
	// initErr is set if the first attempt to initialize the cache
	// fails.
	initErr error

	// ctx is a cache exit context
	ctx context.Context
	// cancel triggers exit context closure
	cancel context.CancelFunc

	// fnCache is used to perform short ttl-based caching of the results of
	// regularly called methods.
	fnCache *utils.FnCache

	trustCache         services.Trust
	clusterConfigCache services.ClusterConfiguration
	provisionerCache   services.Provisioner
	accessCache        services.Access
	dynamicAccessCache services.DynamicAccessExt
	presenceCache      services.Presence
	webSessionCache    types.WebSessionInterface
	webTokenCache      types.WebTokenInterface
	eventsFanout       *services.FanoutSet

	// closed indicates that the cache has been closed
	closed *atomic.Bool
}

// read acquires the cache read lock and selects the appropriate
// target for read operations.  The returned guard *must* be
// released to prevent deadlocks.
func (c *Cache) read() (readGuard, error) {
	if c.closed.Load() {
		return readGuard{}, trace.Errorf("cache is closed")
	}
	c.rw.RLock()
	if c.ok {
		return readGuard{
			trust:         c.trustCache,
			clusterConfig: c.clusterConfigCache,
			provisioner:   c.provisionerCache,
			access:        c.accessCache,
			dynamicAccess: c.dynamicAccessCache,
			presence:      c.presenceCache,
			webSession:    c.webSessionCache,
			webToken:      c.webTokenCache,
			release:       c.rw.RUnlock,
		}, nil
	}
	c.rw.RUnlock()
	return readGuard{
		trust:         c.Config.Trust,
		clusterConfig: c.Config.ClusterConfig,
		provisioner:   c.Config.Provisioner,
		access:        c.Config.Access,
		dynamicAccess: c.Config.DynamicAccess,
		presence:      c.Config.Presence,
		webSession:    c.Config.WebSession,
		release:       nil,
	}, nil
}

// readGuard holds references to a "backend".  if the referenced
// backed is the cache, then readGuard also holds the release
// function for the read lock, and ensures that it is not
// double-called.
type readGuard struct {
	trust         services.Trust
	clusterConfig services.ClusterConfiguration
	provisioner   services.Provisioner
	access        services.Access
	dynamicAccess services.DynamicAccessCore
	presence      services.Presence
	webSession    types.WebSessionInterface
	webToken      types.WebTokenInterface
	release       func()
	released      bool
}

// Release releases the read lock if it is held.  This method
// can be called multiple times, but is not thread-safe.
func (r *readGuard) Release() {
	if r.release != nil && !r.released {
		r.release()
		r.released = true
	}
}

// IsCacheRead checks if this readGuard holds a cache reference.
func (r *readGuard) IsCacheRead() bool {
	return r.release != nil
}

// Config defines cache configuration parameters
type Config struct {
	// target is an identifying string that allows errors to
	// indicate the target presets used (e.g. "auth").
	target string
	// Context is context for parent operations
	Context context.Context
	// Watches provides a list of resources
	// for the cache to watch
	Watches []types.WatchKind
	// Events provides events watchers
	Events types.Events
	// Trust is a service providing information about certificate
	// authorities
	Trust services.Trust
	// ClusterConfig is a cluster configuration service
	ClusterConfig services.ClusterConfiguration
	// Provisioner is a provisioning service
	Provisioner services.Provisioner
	// Access is an access service
	Access services.Access
	// DynamicAccess is a dynamic access service
	DynamicAccess services.DynamicAccessCore
	// Presence is a presence service
	Presence services.Presence
	// WebSession holds regular web sessions.
	WebSession types.WebSessionInterface
	// Backend is a backend for local cache
	Backend backend.Backend
	// MaxRetryPeriod is the maximum period between cache retries on failures
	MaxRetryPeriod time.Duration
	// WatcherInitTimeout is the maximum acceptable delay for an
	// OpInit after a watcher has been started (default=1m).
	WatcherInitTimeout time.Duration
	// CacheInitTimeout is the maximum amount of time that cache.New
	// will block, waiting for initialization (default=20s).
	CacheInitTimeout time.Duration
	// RelativeExpiryCheckInterval determines how often the cache performs special
	// "relative expiration" checks which are used to compensate for real backends
	// that have suffer from overly lazy ttl'ing of resources.
	RelativeExpiryCheckInterval time.Duration
	// RelativeExpiryLimit determines the maximum number of nodes that may be
	// removed during relative expiration.
	RelativeExpiryLimit int
	// EventsC is a channel for event notifications,
	// used in tests
	EventsC chan Event
	// Clock can be set to control time,
	// uses runtime clock by default
	Clock clockwork.Clock
	// Component is a component used in logs
	Component string
	// QueueSize is a desired queue Size
	QueueSize int
	// Tracer is used to create spans
	Tracer oteltrace.Tracer
	// Unstarted indicates that the cache should not be started during New. The
	// cache is usable before it's started, but it will always hit the backend.
	Unstarted bool
}

// CheckAndSetDefaults checks parameters and sets default values
func (c *Config) CheckAndSetDefaults() error {
	if c.Events == nil {
		return trace.BadParameter("missing Events parameter")
	}
	if c.Backend == nil {
		return trace.BadParameter("missing Backend parameter")
	}
	if c.Context == nil {
		c.Context = context.Background()
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.MaxRetryPeriod == 0 {
		c.MaxRetryPeriod = defaults.MaxWatcherBackoff
	}
	if c.WatcherInitTimeout == 0 {
		c.WatcherInitTimeout = time.Minute
	}
	if c.CacheInitTimeout == 0 {
		c.CacheInitTimeout = time.Second * 20
	}
	if c.RelativeExpiryCheckInterval == 0 {
		c.RelativeExpiryCheckInterval = apidefaults.ServerKeepAliveTTL() + 5*time.Second
	}
	if c.RelativeExpiryLimit == 0 {
		c.RelativeExpiryLimit = 2000
	}
	if c.Component == "" {
		c.Component = teleport.ComponentCache
	}
	return nil
}

// Event is event used in tests
type Event struct {
	// Type is event type
	Type string
	// Event is event processed
	// by the event cycle
	Event types.Event
}

const (
	// EventProcessed is emitted whenever event is processed
	EventProcessed = "event_processed"
	// WatcherStarted is emitted when a new event watcher is started
	WatcherStarted = "watcher_started"
	// WatcherFailed is emitted when event watcher has failed
	WatcherFailed = "watcher_failed"
	// Reloading is emitted when an error occurred watching events
	// and the cache is waiting to create a new watcher
	Reloading = "reloading_cache"
	// RelativeExpiry notifies that relative expiry operations have
	// been run.
	RelativeExpiry = "relative_expiry"
)

// New creates a new instance of Cache
func New(config Config) (*Cache, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	clusterConfigCache, err := local.NewClusterConfigurationService(config.Backend)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(config.Context)
	fnCache, err := utils.NewFnCache(utils.FnCacheConfig{
		TTL:     time.Second,
		Clock:   config.Clock,
		Context: ctx,
	})
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	cs := &Cache{
		ctx:                ctx,
		cancel:             cancel,
		Config:             config,
		generation:         atomic.NewUint64(0),
		initC:              make(chan struct{}),
		fnCache:            fnCache,
		trustCache:         local.NewCAService(config.Backend),
		clusterConfigCache: clusterConfigCache,
		provisionerCache:   local.NewProvisioningService(config.Backend),
		accessCache:        local.NewAccessService(config.Backend),
		dynamicAccessCache: local.NewDynamicAccessService(config.Backend),
		presenceCache:      local.NewPresenceService(config.Backend),
		eventsFanout:       services.NewFanoutSet(),
		Entry: log.WithFields(log.Fields{
			trace.Component: config.Component,
		}),
		closed: atomic.NewBool(false),
	}

	if config.Unstarted {
		return cs, nil
	}

	if err := cs.Start(); err != nil {
		cs.Close()
		return nil, trace.Wrap(err)
	}

	return cs, nil
}

// Starts the cache. Should only be called once.
func (c *Cache) Start() error {
	select {
	case <-c.initC:
		if c.initErr == nil {
			c.Infof("Cache %q first init succeeded.", c.Config.target)
		} else {
			c.WithError(c.initErr).Warnf("Cache %q first init failed, continuing re-init attempts in background.", c.Config.target)
		}
	case <-c.ctx.Done():
		c.Close()
		return trace.Wrap(c.ctx.Err(), "context closed during cache init")
	case <-time.After(c.Config.CacheInitTimeout):
		c.Warningf("Cache init is taking too long, will continue in background.")
	}
	return nil
}

// NewWatcher returns a new event watcher. In case of a cache
// this watcher will return events as seen by the cache,
// not the backend. This feature allows auth server
// to handle subscribers connected to the in-memory caches
// instead of reading from the backend.
func (c *Cache) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/NewWatcher")
	defer span.End()
Outer:
	for _, requested := range watch.Kinds {
		for _, configured := range c.Config.Watches {
			if requested.Kind == configured.Kind {
				continue Outer
			}
		}
		return nil, trace.BadParameter("cache %q does not support watching resource %q", c.Config.target, requested.Kind)
	}
	return c.eventsFanout.NewWatcher(ctx, watch)
}

// Close closes all outstanding and active cache operations
func (c *Cache) Close() error {
	c.closed.Store(true)
	c.cancel()
	c.eventsFanout.Close()
	return nil
}

type getCertAuthorityCacheKey struct {
	id types.CertAuthID
}

var _ map[getCertAuthorityCacheKey]struct{} // compile-time hashability check

// GetCertAuthority returns certificate authority by given id. Parameter loadSigningKeys
// controls if signing keys are loaded
func (c *Cache) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadSigningKeys bool, opts ...services.MarshalOption) (types.CertAuthority, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetCertAuthority")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	if !rg.IsCacheRead() && !loadSigningKeys {
		ta := func(_ types.CertAuthority) {} // compile-time type assertion
		ci, err := c.fnCache.Get(ctx, getCertAuthorityCacheKey{id}, func(ctx context.Context) (interface{}, error) {
			ca, err := rg.trust.GetCertAuthority(ctx, id, loadSigningKeys, opts...)
			ta(ca)
			return ca, err
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		cachedCA := ci.(types.CertAuthority)
		ta(cachedCA)
		return cachedCA.Clone(), nil
	}

	ca, err := rg.trust.GetCertAuthority(ctx, id, loadSigningKeys, opts...)
	if trace.IsNotFound(err) && rg.IsCacheRead() {
		// release read lock early
		rg.Release()
		// fallback is sane because method is never used
		// in construction of derivative caches.
		if ca, err := c.Config.Trust.GetCertAuthority(ctx, id, loadSigningKeys, opts...); err == nil {
			return ca, nil
		}
	}
	return ca, trace.Wrap(err)
}

type getCertAuthoritiesCacheKey struct {
	caType types.CertAuthType
}

var _ map[getCertAuthoritiesCacheKey]struct{} // compile-time hashability check

// GetCertAuthorities returns a list of authorities of a given type
// loadSigningKeys controls whether signing keys should be loaded or not
func (c *Cache) GetCertAuthorities(ctx context.Context, caType types.CertAuthType, loadSigningKeys bool, opts ...services.MarshalOption) ([]types.CertAuthority, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetCertAuthorities")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	if !rg.IsCacheRead() && !loadSigningKeys {
		ta := func(_ []types.CertAuthority) {} // compile-time type assertion
		ci, err := c.fnCache.Get(ctx, getCertAuthoritiesCacheKey{caType}, func(ctx context.Context) (interface{}, error) {
			cas, err := rg.trust.GetCertAuthorities(ctx, caType, loadSigningKeys, opts...)
			ta(cas)
			return cas, trace.Wrap(err)
		})
		if err != nil || ci == nil {
			return nil, trace.Wrap(err)
		}
		cachedCAs := ci.([]types.CertAuthority)
		ta(cachedCAs)
		cas := make([]types.CertAuthority, 0, len(cachedCAs))
		for _, ca := range cachedCAs {
			cas = append(cas, ca.Clone())
		}
		return cas, nil
	}
	return rg.trust.GetCertAuthorities(ctx, caType, loadSigningKeys, opts...)
}

// GetStaticTokens gets the list of static tokens used to provision nodes.
func (c *Cache) GetStaticTokens() (types.StaticTokens, error) {
	_, span := c.Tracer.Start(context.TODO(), "cache/GetStaticTokens")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.clusterConfig.GetStaticTokens()
}

// GetTokens returns all active (non-expired) provisioning tokens
func (c *Cache) GetTokens(ctx context.Context) ([]types.ProvisionToken, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetTokens")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.provisioner.GetTokens(ctx)
}

// GetToken finds and returns token by ID
func (c *Cache) GetToken(ctx context.Context, name string) (types.ProvisionToken, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetToken")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	token, err := rg.provisioner.GetToken(ctx, name)
	if trace.IsNotFound(err) && rg.IsCacheRead() {
		// release read lock early
		rg.Release()
		// fallback is sane because method is never used
		// in construction of derivative caches.
		if token, err := c.Config.Provisioner.GetToken(ctx, name); err == nil {
			return token, nil
		}
	}
	return token, trace.Wrap(err)
}

type clusterConfigCacheKey struct {
	kind string
}

var _ map[clusterConfigCacheKey]struct{} // compile-time hashability check

// GetClusterNetworkingConfig gets ClusterNetworkingConfig from the backend.
func (c *Cache) GetClusterNetworkingConfig(ctx context.Context, opts ...services.MarshalOption) (types.ClusterNetworkingConfig, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetClusterNetworkingConfig")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	if !rg.IsCacheRead() {
		ta := func(_ types.ClusterNetworkingConfig) {} // compile-time type assertion
		ci, err := c.fnCache.Get(ctx, clusterConfigCacheKey{"networking"}, func(ctx context.Context) (interface{}, error) {
			cfg, err := rg.clusterConfig.GetClusterNetworkingConfig(ctx, opts...)
			ta(cfg)
			return cfg, err
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		cachedCfg := ci.(types.ClusterNetworkingConfig)
		ta(cachedCfg)
		return cachedCfg.Clone(), nil
	}
	return rg.clusterConfig.GetClusterNetworkingConfig(ctx, opts...)
}

// GetClusterName gets the name of the cluster from the backend.
func (c *Cache) GetClusterName(opts ...services.MarshalOption) (types.ClusterName, error) {
	ctx, span := c.Tracer.Start(context.TODO(), "cache/GetClusterName")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	if !rg.IsCacheRead() {
		ta := func(_ types.ClusterName) {} // compile-time type assertion
		ci, err := c.fnCache.Get(ctx, clusterConfigCacheKey{"name"}, func(ctx context.Context) (interface{}, error) {
			cfg, err := rg.clusterConfig.GetClusterName(opts...)
			ta(cfg)
			return cfg, err
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		cachedCfg := ci.(types.ClusterName)
		ta(cachedCfg)
		return cachedCfg.Clone(), nil
	}
	return rg.clusterConfig.GetClusterName(opts...)
}

// GetRoles is a part of auth.Cache implementation
func (c *Cache) GetRoles(ctx context.Context) ([]types.Role, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetRoles")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.access.GetRoles(ctx)
}

// GetRole is a part of auth.Cache implementation
func (c *Cache) GetRole(ctx context.Context, name string) (types.Role, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetRole")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	role, err := rg.access.GetRole(ctx, name)
	if trace.IsNotFound(err) && rg.IsCacheRead() {
		// release read lock early
		rg.Release()
		// fallback is sane because method is never used
		// in construction of derivative caches.
		if role, err := c.Config.Access.GetRole(ctx, name); err == nil {
			return role, nil
		}
	}
	return role, err
}

// GetNamespace returns namespace
func (c *Cache) GetNamespace(name string) (*types.Namespace, error) {
	_, span := c.Tracer.Start(context.TODO(), "cache/GetNamespace")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetNamespace(name)
}

// GetNode finds and returns a node by name and namespace.
func (c *Cache) GetNode(ctx context.Context, namespace, name string) (types.Server, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetNode")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetNode(ctx, namespace, name)
}

type getNodesCacheKey struct {
	namespace string
}

var _ map[getNodesCacheKey]struct{} // compile-time hashability check

// GetNodes is a part of auth.Cache implementation
func (c *Cache) GetNodes(ctx context.Context, namespace string) ([]types.Server, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetNodes")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	if !rg.IsCacheRead() {
		cachedNodes, err := c.getNodesWithTTLCache(ctx, rg, namespace)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		nodes := make([]types.Server, 0, len(cachedNodes))
		for _, node := range cachedNodes {
			nodes = append(nodes, node.DeepCopy())
		}
		return nodes, nil
	}

	return rg.presence.GetNodes(ctx, namespace)
}

// getNodesWithTTLCache implements TTL-based caching for the GetNodes endpoint.  All nodes that will be returned from the caching layer
// must be cloned to avoid concurrent modification.
func (c *Cache) getNodesWithTTLCache(ctx context.Context, rg readGuard, namespace string, opts ...services.MarshalOption) ([]types.Server, error) {
	ta := func(_ []types.Server) {} // compile-time type assertion
	ni, err := c.fnCache.Get(ctx, getNodesCacheKey{namespace}, func(ctx context.Context) (interface{}, error) {
		nodes, err := rg.presence.GetNodes(ctx, namespace)
		ta(nodes)
		return nodes, err
	})
	if err != nil || ni == nil {
		return nil, trace.Wrap(err)
	}
	cachedNodes, ok := ni.([]types.Server)
	if !ok {
		return nil, trace.Errorf("TTL-cache returned unexpexted type %T (this is a bug!).", ni)
	}
	ta(cachedNodes)
	return cachedNodes, nil
}

// GetReverseTunnels is a part of auth.Cache implementation
func (c *Cache) GetReverseTunnels(ctx context.Context, opts ...services.MarshalOption) ([]types.ReverseTunnel, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetReverseTunnels")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetReverseTunnels(ctx, opts...)
}

// GetProxies is a part of auth.Cache implementation
func (c *Cache) GetProxies() ([]types.Server, error) {
	_, span := c.Tracer.Start(context.TODO(), "cache/GetProxies")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.presence.GetProxies()
}

type remoteClustersCacheKey struct {
	name string
}

var _ map[remoteClustersCacheKey]struct{} // compile-time hashability check

// GetRemoteCluster returns a remote cluster by name
func (c *Cache) GetRemoteCluster(clusterName string) (types.RemoteCluster, error) {
	ctx, span := c.Tracer.Start(context.TODO(), "cache/GetRemoteCluster")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	if !rg.IsCacheRead() {
		ta := func(_ types.RemoteCluster) {} // compile-time type assertion
		ri, err := c.fnCache.Get(ctx, remoteClustersCacheKey{clusterName}, func(ctx context.Context) (interface{}, error) {
			remote, err := rg.presence.GetRemoteCluster(clusterName)
			ta(remote)
			return remote, err
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		cachedRemote := ri.(types.RemoteCluster)
		ta(cachedRemote)
		return cachedRemote.Clone(), nil
	}
	rc, err := rg.presence.GetRemoteCluster(clusterName)
	if trace.IsNotFound(err) && rg.IsCacheRead() {
		// release read lock early
		rg.Release()
		// fallback is sane because this method is never used
		// in construction of derivative caches.
		if rc, err := c.Config.Presence.GetRemoteCluster(clusterName); err == nil {
			return rc, nil
		}
	}
	return rc, trace.Wrap(err)
}

// GetWebSession gets a regular web session.
func (c *Cache) GetWebSession(ctx context.Context, req types.GetWebSessionRequest) (types.WebSession, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetWebSession")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.webSession.Get(ctx, req)
}

// GetWebToken gets a web token.
func (c *Cache) GetWebToken(ctx context.Context, req types.GetWebTokenRequest) (types.WebToken, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetWebToken")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.webToken.Get(ctx, req)
}

// GetAuthPreference gets the cluster authentication config.
func (c *Cache) GetAuthPreference(ctx context.Context) (types.AuthPreference, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetAuthPreference")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.clusterConfig.GetAuthPreference(ctx)
}

// GetLock gets a lock by name.
func (c *Cache) GetLock(ctx context.Context, name string) (types.Lock, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetLock")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	lock, err := rg.access.GetLock(ctx, name)
	if trace.IsNotFound(err) && rg.IsCacheRead() {
		// release read lock early
		rg.Release()
		// fallback is sane because method is never used
		// in construction of derivative caches.
		if lock, err := c.Config.Access.GetLock(ctx, name); err == nil {
			return lock, nil
		}
	}
	return lock, trace.Wrap(err)
}

// GetLocks gets all/in-force locks that match at least one of the targets
// when specified.
func (c *Cache) GetLocks(ctx context.Context, inForceOnly bool, targets ...types.LockTarget) ([]types.Lock, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetLocks")
	defer span.End()

	rg, err := c.read()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()
	return rg.access.GetLocks(ctx, inForceOnly, targets...)
}
