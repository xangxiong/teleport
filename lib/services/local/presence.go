/*
Copyright 2015-2020 Gravitational, Inc.

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
	"context"
	"sort"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// PresenceService records and reports the presence of all components
// of the cluster - Nodes, Proxies and SSH nodes
type PresenceService struct {
	log    *logrus.Entry
	jitter utils.Jitter
	backend.Backend
}

// backendItemToResourceFunc defines a function that unmarshals a
// `backend.Item` into the implementation of `types.Resource`.
type backendItemToResourceFunc func(item backend.Item) (types.ResourceWithLabels, error)

// NewPresenceService returns new presence service instance
func NewPresenceService(b backend.Backend) *PresenceService {
	return &PresenceService{
		log:     logrus.WithFields(logrus.Fields{trace.Component: "Presence"}),
		jitter:  utils.NewFullJitter(),
		Backend: b,
	}
}

// GetNamespace returns a namespace by name
func (s *PresenceService) GetNamespace(name string) (*types.Namespace, error) {
	if name == "" {
		return nil, trace.BadParameter("missing namespace name")
	}
	item, err := s.Get(context.TODO(), backend.Key(namespacesPrefix, name, paramsPrefix))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("namespace %q is not found", name)
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalNamespace(
		item.Value, services.WithResourceID(item.ID), services.WithExpires(item.Expires))
}

func (s *PresenceService) getServers(ctx context.Context, kind, prefix string) ([]types.Server, error) {
	result, err := s.GetRange(ctx, backend.Key(prefix), backend.RangeEnd(backend.Key(prefix)), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	servers := make([]types.Server, len(result.Items))
	for i, item := range result.Items {
		server, err := services.UnmarshalServer(
			item.Value, kind,
			services.WithResourceID(item.ID),
			services.WithExpires(item.Expires),
		)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		servers[i] = server
	}
	// sorting helps with tests and makes it all deterministic
	sort.Sort(services.SortedServers(servers))
	return servers, nil
}

func (s *PresenceService) upsertServer(ctx context.Context, prefix string, server types.Server) error {
	value, err := services.MarshalServer(server)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = s.Put(ctx, backend.Item{
		Key:     backend.Key(prefix, server.GetName()),
		Value:   value,
		Expires: server.Expiry(),
		ID:      server.GetResourceID(),
	})
	return trace.Wrap(err)
}

// DeleteAllNodes deletes all nodes in a namespace
func (s *PresenceService) DeleteAllNodes(ctx context.Context, namespace string) error {
	startKey := backend.Key(nodesPrefix, namespace)
	return s.DeleteRange(ctx, startKey, backend.RangeEnd(startKey))
}

// DeleteNode deletes node
func (s *PresenceService) DeleteNode(ctx context.Context, namespace string, name string) error {
	key := backend.Key(nodesPrefix, namespace, name)
	return s.Delete(ctx, key)
}

// GetNode returns a node by name and namespace.
func (s *PresenceService) GetNode(ctx context.Context, namespace, name string) (types.Server, error) {
	if namespace == "" {
		return nil, trace.BadParameter("missing parameter namespace")
	}
	if name == "" {
		return nil, trace.BadParameter("missing parameter name")
	}
	item, err := s.Get(ctx, backend.Key(nodesPrefix, namespace, name))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalServer(
		item.Value,
		types.KindNode,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
}

// GetNodes returns a list of registered servers
func (s *PresenceService) GetNodes(ctx context.Context, namespace string) ([]types.Server, error) {
	if namespace == "" {
		return nil, trace.BadParameter("missing namespace value")
	}

	// Get all items in the bucket.
	startKey := backend.Key(nodesPrefix, namespace)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Marshal values into a []services.Server slice.
	servers := make([]types.Server, len(result.Items))
	for i, item := range result.Items {
		server, err := services.UnmarshalServer(
			item.Value,
			types.KindNode,
			[]services.MarshalOption{
				services.WithResourceID(item.ID),
				services.WithExpires(item.Expires),
			}...,
		)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		servers[i] = server
	}

	return servers, nil
}

// UpsertNode registers node presence, permanently if TTL is 0 or for the
// specified duration with second resolution if it's >= 1 second.
func (s *PresenceService) UpsertNode(ctx context.Context, server types.Server) (*types.KeepAlive, error) {
	if server.GetNamespace() == "" {
		return nil, trace.BadParameter("missing node namespace")
	}
	value, err := services.MarshalServer(server)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lease, err := s.Put(ctx, backend.Item{
		Key:     backend.Key(nodesPrefix, server.GetNamespace(), server.GetName()),
		Value:   value,
		Expires: server.Expiry(),
		ID:      server.GetResourceID(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if server.Expiry().IsZero() {
		return &types.KeepAlive{}, nil
	}
	return &types.KeepAlive{
		Type:    types.KeepAlive_NODE,
		LeaseID: lease.ID,
		Name:    server.GetName(),
	}, nil
}

// KeepAliveServer updates expiry time of a server resource.
func (s *PresenceService) KeepAliveServer(ctx context.Context, h types.KeepAlive) error {
	if err := h.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	// Update the prefix off the type information in the keep alive.
	var key []byte
	switch h.GetType() {
	case constants.KeepAliveNode:
		key = backend.Key(nodesPrefix, h.Namespace, h.Name)
	default:
		return trace.BadParameter("unknown keep-alive type %q", h.GetType())
	}

	err := s.KeepAlive(ctx, backend.Lease{
		ID:  h.LeaseID,
		Key: key,
	}, h.Expires)
	return trace.Wrap(err)
}

// GetAuthServers returns a list of registered servers
func (s *PresenceService) GetAuthServers() ([]types.Server, error) {
	return s.getServers(context.TODO(), types.KindAuthServer, authServersPrefix)
}

// UpsertAuthServer registers auth server presence, permanently if ttl is 0 or
// for the specified duration with second resolution if it's >= 1 second
func (s *PresenceService) UpsertAuthServer(server types.Server) error {
	return s.upsertServer(context.TODO(), authServersPrefix, server)
}

// DeleteAllAuthServers deletes all auth servers
func (s *PresenceService) DeleteAllAuthServers() error {
	startKey := backend.Key(authServersPrefix)
	return s.DeleteRange(context.TODO(), startKey, backend.RangeEnd(startKey))
}

// DeleteAuthServer deletes auth server by name
func (s *PresenceService) DeleteAuthServer(name string) error {
	key := backend.Key(authServersPrefix, name)
	return s.Delete(context.TODO(), key)
}

// UpsertProxy registers proxy server presence, permanently if ttl is 0 or
// for the specified duration with second resolution if it's >= 1 second
func (s *PresenceService) UpsertProxy(server types.Server) error {
	return s.upsertServer(context.TODO(), proxiesPrefix, server)
}

// GetProxies returns a list of registered proxies
func (s *PresenceService) GetProxies() ([]types.Server, error) {
	return s.getServers(context.TODO(), types.KindProxy, proxiesPrefix)
}

// DeleteAllReverseTunnels deletes all reverse tunnels
func (s *PresenceService) DeleteAllReverseTunnels() error {
	startKey := backend.Key(reverseTunnelsPrefix)
	return s.DeleteRange(context.TODO(), startKey, backend.RangeEnd(startKey))
}

// UpsertReverseTunnel upserts reverse tunnel entry temporarily or permanently
func (s *PresenceService) UpsertReverseTunnel(tunnel types.ReverseTunnel) error {
	if err := services.ValidateReverseTunnel(tunnel); err != nil {
		return trace.Wrap(err)
	}
	value, err := services.MarshalReverseTunnel(tunnel)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = s.Put(context.TODO(), backend.Item{
		Key:     backend.Key(reverseTunnelsPrefix, tunnel.GetName()),
		Value:   value,
		Expires: tunnel.Expiry(),
		ID:      tunnel.GetResourceID(),
	})
	return trace.Wrap(err)
}

// GetReverseTunnels returns a list of registered servers
func (s *PresenceService) GetReverseTunnels(ctx context.Context, opts ...services.MarshalOption) ([]types.ReverseTunnel, error) {
	startKey := backend.Key(reverseTunnelsPrefix)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tunnels := make([]types.ReverseTunnel, len(result.Items))
	if len(result.Items) == 0 {
		return tunnels, nil
	}
	for i, item := range result.Items {
		tunnel, err := services.UnmarshalReverseTunnel(
			item.Value, services.AddOptions(opts, services.WithResourceID(item.ID), services.WithExpires(item.Expires))...)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		tunnels[i] = tunnel
	}
	// sorting helps with tests and makes it all deterministic
	sort.Sort(services.SortedReverseTunnels(tunnels))
	return tunnels, nil
}

// DeleteReverseTunnel deletes reverse tunnel by it's cluster name
func (s *PresenceService) DeleteReverseTunnel(clusterName string) error {
	err := s.Delete(context.TODO(), backend.Key(reverseTunnelsPrefix, clusterName))
	return trace.Wrap(err)
}

// UpsertTrustedCluster creates or updates a TrustedCluster in the backend.
func (s *PresenceService) UpsertTrustedCluster(ctx context.Context, trustedCluster types.TrustedCluster) (types.TrustedCluster, error) {
	if err := services.ValidateTrustedCluster(trustedCluster); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.MarshalTrustedCluster(trustedCluster)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	_, err = s.Put(ctx, backend.Item{
		Key:     backend.Key(trustedClustersPrefix, trustedCluster.GetName()),
		Value:   value,
		Expires: trustedCluster.Expiry(),
		ID:      trustedCluster.GetResourceID(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return trustedCluster, nil
}

// GetTrustedCluster returns a single TrustedCluster by name.
func (s *PresenceService) GetTrustedCluster(ctx context.Context, name string) (types.TrustedCluster, error) {
	if name == "" {
		return nil, trace.BadParameter("missing trusted cluster name")
	}
	item, err := s.Get(ctx, backend.Key(trustedClustersPrefix, name))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalTrustedCluster(item.Value, services.WithResourceID(item.ID), services.WithExpires(item.Expires))
}

// GetTrustedClusters returns all TrustedClusters in the backend.
func (s *PresenceService) GetTrustedClusters(ctx context.Context) ([]types.TrustedCluster, error) {
	startKey := backend.Key(trustedClustersPrefix)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	out := make([]types.TrustedCluster, len(result.Items))
	for i, item := range result.Items {
		tc, err := services.UnmarshalTrustedCluster(item.Value,
			services.WithResourceID(item.ID), services.WithExpires(item.Expires))
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out[i] = tc
	}

	sort.Sort(types.SortedTrustedCluster(out))
	return out, nil
}

// DeleteTrustedCluster removes a TrustedCluster from the backend by name.
func (s *PresenceService) DeleteTrustedCluster(ctx context.Context, name string) error {
	if name == "" {
		return trace.BadParameter("missing trusted cluster name")
	}
	err := s.Delete(ctx, backend.Key(trustedClustersPrefix, name))
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("trusted cluster %q is not found", name)
		}
	}
	return trace.Wrap(err)
}

// UpsertTunnelConnection updates or creates tunnel connection
func (s *PresenceService) UpsertTunnelConnection(conn types.TunnelConnection) error {
	if err := conn.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	value, err := services.MarshalTunnelConnection(conn)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = s.Put(context.TODO(), backend.Item{
		Key:     backend.Key(tunnelConnectionsPrefix, conn.GetClusterName(), conn.GetName()),
		Value:   value,
		Expires: conn.Expiry(),
		ID:      conn.GetResourceID(),
	})
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetTunnelConnection returns connection by cluster name and connection name
func (s *PresenceService) GetTunnelConnection(clusterName, connectionName string, opts ...services.MarshalOption) (types.TunnelConnection, error) {
	item, err := s.Get(context.TODO(), backend.Key(tunnelConnectionsPrefix, clusterName, connectionName))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("trusted cluster connection %q is not found", connectionName)
		}
		return nil, trace.Wrap(err)
	}
	conn, err := services.UnmarshalTunnelConnection(item.Value,
		services.AddOptions(opts, services.WithResourceID(item.ID), services.WithExpires(item.Expires))...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return conn, nil
}

// GetAllTunnelConnections returns all tunnel connections
func (s *PresenceService) GetAllTunnelConnections(opts ...services.MarshalOption) ([]types.TunnelConnection, error) {
	startKey := backend.Key(tunnelConnectionsPrefix)
	result, err := s.GetRange(context.TODO(), startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conns := make([]types.TunnelConnection, len(result.Items))
	for i, item := range result.Items {
		conn, err := services.UnmarshalTunnelConnection(item.Value,
			services.AddOptions(opts,
				services.WithResourceID(item.ID),
				services.WithExpires(item.Expires))...)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		conns[i] = conn
	}

	return conns, nil
}

// DeleteTunnelConnection deletes tunnel connection by name
func (s *PresenceService) DeleteTunnelConnection(clusterName, connectionName string) error {
	if clusterName == "" {
		return trace.BadParameter("missing cluster name")
	}
	if connectionName == "" {
		return trace.BadParameter("missing connection name")
	}
	return s.Delete(context.TODO(), backend.Key(tunnelConnectionsPrefix, clusterName, connectionName))
}

// DeleteTunnelConnections deletes all tunnel connections for cluster
func (s *PresenceService) DeleteTunnelConnections(clusterName string) error {
	if clusterName == "" {
		return trace.BadParameter("missing cluster name")
	}
	startKey := backend.ExactKey(tunnelConnectionsPrefix, clusterName)
	err := s.DeleteRange(context.TODO(), startKey, backend.RangeEnd(startKey))
	return trace.Wrap(err)
}

// DeleteAllTunnelConnections deletes all tunnel connections
func (s *PresenceService) DeleteAllTunnelConnections() error {
	startKey := backend.Key(tunnelConnectionsPrefix)
	err := s.DeleteRange(context.TODO(), startKey, backend.RangeEnd(startKey))
	return trace.Wrap(err)
}

// GetRemoteClusters returns a list of remote clusters
func (s *PresenceService) GetRemoteClusters(opts ...services.MarshalOption) ([]types.RemoteCluster, error) {
	startKey := backend.Key(remoteClustersPrefix)
	result, err := s.GetRange(context.TODO(), startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusters := make([]types.RemoteCluster, len(result.Items))
	for i, item := range result.Items {
		cluster, err := services.UnmarshalRemoteCluster(item.Value,
			services.AddOptions(opts, services.WithResourceID(item.ID), services.WithExpires(item.Expires))...)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		clusters[i] = cluster
	}
	return clusters, nil
}

// getRemoteCluster returns a remote cluster in raw form and unmarshaled
func (s *PresenceService) getRemoteCluster(clusterName string) (*backend.Item, types.RemoteCluster, error) {
	if clusterName == "" {
		return nil, nil, trace.BadParameter("missing parameter cluster name")
	}
	item, err := s.Get(context.TODO(), backend.Key(remoteClustersPrefix, clusterName))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, nil, trace.NotFound("remote cluster %q is not found", clusterName)
		}
		return nil, nil, trace.Wrap(err)
	}
	rc, err := services.UnmarshalRemoteCluster(item.Value,
		services.WithResourceID(item.ID), services.WithExpires(item.Expires))
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return item, rc, nil
}

// GetRemoteCluster returns a remote cluster by name
func (s *PresenceService) GetRemoteCluster(clusterName string) (types.RemoteCluster, error) {
	_, rc, err := s.getRemoteCluster(clusterName)
	return rc, trace.Wrap(err)
}

// this combination of backoff parameters leads to worst-case total time spent
// in backoff between 1ms and 2000ms depending on jitter.  tests are in
// place to verify that this is sufficient to resolve a 20-lease contention
// event, which is worse than should ever occur in practice.
const baseBackoff = time.Millisecond * 400
const leaseRetryAttempts int64 = 6

// AcquireSemaphore attempts to acquire the specified semaphore.  AcquireSemaphore will automatically handle
// retry on contention.  If the semaphore has already reached MaxLeases, or there is too much contention,
// a LimitExceeded error is returned (contention in this context means concurrent attempts to update the
// *same* semaphore, separate semaphores can be modified concurrently without issue).  Note that this function
// is the only semaphore method that handles retries internally.  This is because this method both blocks
// user-facing operations, and contains multiple different potential contention points.
func (s *PresenceService) AcquireSemaphore(ctx context.Context, req types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	if err := req.Check(); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.Expires.Before(s.Clock().Now().UTC()) {
		return nil, trace.BadParameter("cannot acquire expired semaphore lease")
	}

	leaseID := uuid.New().String()

	// key is not modified, so allocate it once
	key := backend.Key(semaphoresPrefix, req.SemaphoreKind, req.SemaphoreName)

Acquire:
	for i := int64(0); i < leaseRetryAttempts; i++ {
		if i > 0 {
			// Not our first attempt, apply backoff. If we knew that we were only in
			// contention with one other acquire attempt we could retry immediately
			// since we got here because some other attempt *succeeded*.  It is safer,
			// however, to assume that we are under high contention and attempt to
			// spread out retries via random backoff.
			select {
			case <-time.After(s.jitter(baseBackoff * time.Duration(i))):
			case <-ctx.Done():
				return nil, trace.Wrap(ctx.Err())
			}
		}

		// attempt to acquire an existing semaphore
		lease, err := s.acquireSemaphore(ctx, key, leaseID, req)
		switch {
		case err == nil:
			// acquire was successful, return the lease.
			return lease, nil
		case trace.IsNotFound(err):
			// semaphore does not exist, attempt to perform a
			// simultaneous init+acquire.
			lease, err = s.initSemaphore(ctx, key, leaseID, req)
			if err != nil {
				if trace.IsAlreadyExists(err) {
					// semaphore was concurrently created
					continue Acquire
				}
				return nil, trace.Wrap(err)
			}
			return lease, nil
		case trace.IsCompareFailed(err):
			// semaphore was concurrently updated
			continue Acquire
		default:
			// If we get here then we encountered an error other than NotFound or CompareFailed,
			// meaning that contention isn't the issue.  No point in re-attempting.
			return nil, trace.Wrap(err)
		}
	}
	return nil, trace.LimitExceeded("too much contention on semaphore %s/%s", req.SemaphoreKind, req.SemaphoreName)
}

// initSemaphore attempts to initialize/acquire a semaphore which does not yet exist.
// Returns AlreadyExistsError if the semaphore is concurrently created.
func (s *PresenceService) initSemaphore(ctx context.Context, key []byte, leaseID string, req types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	// create a new empty semaphore resource configured to specifically match
	// this acquire request.
	sem, err := req.ConfigureSemaphore()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lease, err := sem.Acquire(leaseID, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.MarshalSemaphore(sem)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := backend.Item{
		Key:     key,
		Value:   value,
		Expires: sem.Expiry(),
	}
	_, err = s.Create(ctx, item)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return lease, nil
}

// acquireSemaphore attempts to acquire an existing semaphore.  Returns NotFoundError if no semaphore exists,
// and CompareFailed if the semaphore was concurrently updated.
func (s *PresenceService) acquireSemaphore(ctx context.Context, key []byte, leaseID string, req types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	item, err := s.Get(ctx, key)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sem, err := services.UnmarshalSemaphore(item.Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sem.RemoveExpiredLeases(s.Clock().Now().UTC())

	lease, err := sem.Acquire(leaseID, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	newValue, err := services.MarshalSemaphore(sem)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	newItem := backend.Item{
		Key:     key,
		Value:   newValue,
		Expires: sem.Expiry(),
	}

	if _, err := s.CompareAndSwap(ctx, *item, newItem); err != nil {
		return nil, trace.Wrap(err)
	}
	return lease, nil
}

// KeepAliveSemaphoreLease updates semaphore lease, if the lease expiry is updated,
// semaphore is renewed
func (s *PresenceService) KeepAliveSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	if err := lease.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if lease.Expires.Before(s.Clock().Now().UTC()) {
		return trace.BadParameter("lease %v has expired at %v", lease.LeaseID, lease.Expires)
	}

	key := backend.Key(semaphoresPrefix, lease.SemaphoreKind, lease.SemaphoreName)
	item, err := s.Get(ctx, key)
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("cannot keepalive, semaphore not found: %s/%s", lease.SemaphoreKind, lease.SemaphoreName)
		}
		return trace.Wrap(err)
	}

	sem, err := services.UnmarshalSemaphore(item.Value)
	if err != nil {
		return trace.Wrap(err)
	}

	sem.RemoveExpiredLeases(s.Clock().Now().UTC())

	if err := sem.KeepAlive(lease); err != nil {
		return trace.Wrap(err)
	}

	newValue, err := services.MarshalSemaphore(sem)
	if err != nil {
		return trace.Wrap(err)
	}

	newItem := backend.Item{
		Key:     key,
		Value:   newValue,
		Expires: sem.Expiry(),
	}

	_, err = s.CompareAndSwap(ctx, *item, newItem)
	if err != nil {
		if trace.IsCompareFailed(err) {
			return trace.CompareFailed("semaphore %v/%v has been concurrently updated, try again", sem.GetSubKind(), sem.GetName())
		}
		return trace.Wrap(err)
	}
	return nil
}

// CancelSemaphoreLease cancels semaphore lease early.
func (s *PresenceService) CancelSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	if err := lease.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if lease.Expires.Before(s.Clock().Now()) {
		return trace.BadParameter("the lease %v has expired at %v", lease.LeaseID, lease.Expires)
	}

	for i := int64(0); i < leaseRetryAttempts; i++ {
		if i > 0 {
			// Not our first attempt, apply backoff. If we knew that we were only in
			// contention with one other cancel attempt we could retry immediately
			// since we got here because some other attempt *succeeded*.  It is safer,
			// however, to assume that we are under high contention and attempt to
			// spread out retries via random backoff.
			select {
			case <-time.After(s.jitter(baseBackoff * time.Duration(i))):
			case <-ctx.Done():
				return trace.Wrap(ctx.Err())
			}
		}

		key := backend.Key(semaphoresPrefix, lease.SemaphoreKind, lease.SemaphoreName)
		item, err := s.Get(ctx, key)
		if err != nil {
			return trace.Wrap(err)
		}

		sem, err := services.UnmarshalSemaphore(item.Value)
		if err != nil {
			return trace.Wrap(err)
		}

		if err := sem.Cancel(lease); err != nil {
			return trace.Wrap(err)
		}

		newValue, err := services.MarshalSemaphore(sem)
		if err != nil {
			return trace.Wrap(err)
		}

		newItem := backend.Item{
			Key:     key,
			Value:   newValue,
			Expires: sem.Expiry(),
		}

		_, err = s.CompareAndSwap(ctx, *item, newItem)
		switch {
		case err == nil:
			return nil
		case trace.IsCompareFailed(err):
			// semaphore was concurrently updated
			continue
		default:
			return trace.Wrap(err)
		}
	}

	return trace.LimitExceeded("too much contention on semaphore %s/%s", lease.SemaphoreKind, lease.SemaphoreName)
}

// GetSemaphores returns all semaphores matching the supplied filter.
func (s *PresenceService) GetSemaphores(ctx context.Context, filter types.SemaphoreFilter) ([]types.Semaphore, error) {
	var items []backend.Item
	if filter.SemaphoreKind != "" && filter.SemaphoreName != "" {
		// special case: filter corresponds to a single semaphore
		item, err := s.Get(ctx, backend.Key(semaphoresPrefix, filter.SemaphoreKind, filter.SemaphoreName))
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, nil
			}
			return nil, trace.Wrap(err)
		}
		items = append(items, *item)
	} else {
		var startKey []byte
		if filter.SemaphoreKind != "" {
			startKey = backend.Key(semaphoresPrefix, filter.SemaphoreKind)
		} else {
			startKey = backend.Key(semaphoresPrefix)
		}
		result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, nil
			}
			return nil, trace.Wrap(err)
		}
		items = result.Items
	}

	sems := make([]types.Semaphore, 0, len(items))

	for _, item := range items {
		sem, err := services.UnmarshalSemaphore(item.Value)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if filter.Match(sem) {
			sems = append(sems, sem)
		}
	}

	return sems, nil
}

// DeleteSemaphore deletes a semaphore matching the supplied filter
func (s *PresenceService) DeleteSemaphore(ctx context.Context, filter types.SemaphoreFilter) error {
	if filter.SemaphoreKind == "" || filter.SemaphoreName == "" {
		return trace.BadParameter("semaphore kind and name must be specified for deletion")
	}
	return trace.Wrap(s.Delete(ctx, backend.Key(semaphoresPrefix, filter.SemaphoreKind, filter.SemaphoreName)))
}

// UpsertHostUserInteractionTime upserts a unix user's interaction time
func (s *PresenceService) UpsertHostUserInteractionTime(ctx context.Context, name string, loginTime time.Time) error {
	val, err := utils.FastMarshal(loginTime.UTC())
	if err != nil {
		return err
	}
	_, err = s.Put(ctx, backend.Item{
		Key:   backend.Key(loginTimePrefix, name),
		Value: val,
	})
	return trace.Wrap(err)
}

// GetHostUserInteractionTime retrieves a unix user's interaction time
func (s *PresenceService) GetHostUserInteractionTime(ctx context.Context, name string) (time.Time, error) {
	item, err := s.Get(ctx, backend.Key(loginTimePrefix, name))
	if err != nil {
		return time.Time{}, trace.Wrap(err)
	}
	var t time.Time
	if err := utils.FastUnmarshal(item.Value, &t); err != nil {
		return time.Time{}, trace.Wrap(err)
	}
	return t, nil
}

// ListResources returns a paginated list of resources.
// It implements various filtering for scenarios where the call comes directly
// here (without passing through the RBAC).
func (s *PresenceService) ListResources(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	switch {
	case req.RequiresFakePagination():
		return s.listResourcesWithSort(ctx, req)
	default:
		return s.listResources(ctx, req)
	}
}

func (s *PresenceService) listResources(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	var keyPrefix []string
	var unmarshalItemFunc backendItemToResourceFunc

	switch req.ResourceType {
	case types.KindNode:
		keyPrefix = []string{nodesPrefix, req.Namespace}
		unmarshalItemFunc = backendItemToServer(types.KindNode)
	default:
		return nil, trace.NotImplemented("%s not implemented at ListResources", req.ResourceType)
	}

	rangeStart := backend.Key(append(keyPrefix, req.StartKey)...)
	rangeEnd := backend.RangeEnd(backend.Key(keyPrefix...))
	filter := services.MatchResourceFilter{
		ResourceKind:        req.ResourceType,
		Labels:              req.Labels,
		SearchKeywords:      req.SearchKeywords,
		PredicateExpression: req.PredicateExpression,
	}

	// Get most limit+1 results to determine if there will be a next key.
	reqLimit := int(req.Limit)
	maxLimit := reqLimit + 1
	var resources []types.ResourceWithLabels
	if err := backend.IterateRange(ctx, s.Backend, rangeStart, rangeEnd, maxLimit, func(items []backend.Item) (stop bool, err error) {
		for _, item := range items {
			if len(resources) == maxLimit {
				break
			}

			resource, err := unmarshalItemFunc(item)
			if err != nil {
				return false, trace.Wrap(err)
			}

			switch match, err := services.MatchResourceByFilters(resource, filter, nil /* ignore dup matches */); {
			case err != nil:
				return false, trace.Wrap(err)
			case match:
				resources = append(resources, resource)
			}
		}

		return len(resources) == maxLimit, nil
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	var nextKey string
	if len(resources) > reqLimit {
		nextKey = backend.GetPaginationKey(resources[len(resources)-1])
		// Truncate the last item that was used to determine next row existence.
		resources = resources[:reqLimit]
	}

	return &types.ListResourcesResponse{
		Resources: resources,
		NextKey:   nextKey,
	}, nil
}

// listResourcesWithSort supports sorting by falling back to retrieving all resources
// with GetXXXs, filter, and then fake pagination.
func (s *PresenceService) listResourcesWithSort(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	var resources []types.ResourceWithLabels
	switch req.ResourceType {
	case types.KindNode:
		nodes, err := s.GetNodes(ctx, req.Namespace)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		servers := types.Servers(nodes)
		if err := servers.SortByCustom(req.SortBy); err != nil {
			return nil, trace.Wrap(err)
		}
		resources = servers.AsResources()
	default:
		return nil, trace.NotImplemented("resource type %q is not supported for ListResourcesWithSort", req.ResourceType)
	}

	return FakePaginate(resources, req)
}

// FakePaginate is used when we are working with an entire list of resources upfront but still requires pagination.
// While applying filters, it will also deduplicate matches found.
func FakePaginate(resources []types.ResourceWithLabels, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	limit := int(req.Limit)
	var filtered []types.ResourceWithLabels
	filter := services.MatchResourceFilter{
		ResourceKind:        req.ResourceType,
		Labels:              req.Labels,
		SearchKeywords:      req.SearchKeywords,
		PredicateExpression: req.PredicateExpression,
	}

	// Iterate and filter every resource, deduplicating while matching.
	seenResourceMap := make(map[services.ResourceSeenKey]struct{})
	for _, resource := range resources {
		switch match, err := services.MatchResourceByFilters(resource, filter, seenResourceMap); {
		case err != nil:
			return nil, trace.Wrap(err)
		case !match:
			continue
		}

		filtered = append(filtered, resource)
	}

	totalCount := len(filtered)
	pageStart := 0
	pageEnd := limit

	// Trim resources that precede start key.
	if req.StartKey != "" {
		for i, resource := range filtered {
			if backend.GetPaginationKey(resource) == req.StartKey {
				pageStart = i
				break
			}
		}
		pageEnd = limit + pageStart
	}

	var nextKey string
	if pageEnd >= len(filtered) {
		pageEnd = len(filtered)
	} else {
		nextKey = backend.GetPaginationKey(filtered[pageEnd])
	}

	return &types.ListResourcesResponse{
		Resources:  filtered[pageStart:pageEnd],
		NextKey:    nextKey,
		TotalCount: totalCount,
	}, nil
}

// backendItemToServer returns `backendItemToResourceFunc` to unmarshal a
// `backend.Item` into a `types.ServerV2` with a specific `kind`, returning it
// as a `types.Resource`.
func backendItemToServer(kind string) backendItemToResourceFunc {
	return func(item backend.Item) (types.ResourceWithLabels, error) {
		return services.UnmarshalServer(
			item.Value, kind,
			services.WithResourceID(item.ID),
			services.WithExpires(item.Expires),
		)
	}
}

const (
	reverseTunnelsPrefix    = "reverseTunnels"
	tunnelConnectionsPrefix = "tunnelConnections"
	trustedClustersPrefix   = "trustedclusters"
	remoteClustersPrefix    = "remoteClusters"
	nodesPrefix             = "nodes"
	appServersPrefix        = "appServers"
	namespacesPrefix        = "namespaces"
	authServersPrefix       = "authservers"
	proxiesPrefix           = "proxies"
	semaphoresPrefix        = "semaphores"
	loginTimePrefix         = "hostuser_interaction_time"
)
