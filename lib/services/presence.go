/*
Copyright 2021 Gravitational, Inc.

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

package services

import (
	"context"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
)

// ProxyGetter is a service that gets proxies.
type ProxyGetter interface {
	// GetProxies returns a list of registered proxies.
	GetProxies() ([]types.Server, error)
}

// NodesGetter is a service that gets nodes.
type NodesGetter interface {
	// GetNodes returns a list of registered servers.
	GetNodes(ctx context.Context, namespace string) ([]types.Server, error)
}

// Presence records and reports the presence of all components
// of the cluster - Nodes, Proxies and SSH nodes
type Presence interface {
	// Semaphores is responsible for semaphore handling
	types.Semaphores

	// GetNode returns a node by name and namespace.
	GetNode(ctx context.Context, namespace, name string) (types.Server, error)

	// NodesGetter gets nodes
	NodesGetter

	// DeleteAllNodes deletes all nodes in a namespace.
	DeleteAllNodes(ctx context.Context, namespace string) error

	// DeleteNode deletes node in a namespace
	DeleteNode(ctx context.Context, namespace, name string) error

	// UpsertNode registers node presence, permanently if TTL is 0 or for the
	// specified duration with second resolution if it's >= 1 second.
	UpsertNode(ctx context.Context, server types.Server) (*types.KeepAlive, error)

	// UpsertAuthServer registers auth server presence, permanently if ttl is 0 or
	// for the specified duration with second resolution if it's >= 1 second
	UpsertAuthServer(server types.Server) error

	// UpsertProxy registers proxy server presence, permanently if ttl is 0 or
	// for the specified duration with second resolution if it's >= 1 second
	UpsertProxy(server types.Server) error

	// ProxyGetter gets a list of proxies
	ProxyGetter

	// UpsertReverseTunnel upserts reverse tunnel entry temporarily or permanently
	UpsertReverseTunnel(tunnel types.ReverseTunnel) error

	// GetReverseTunnels returns a list of registered servers
	GetReverseTunnels(ctx context.Context, opts ...MarshalOption) ([]types.ReverseTunnel, error)

	// GetNamespace returns namespace by name
	GetNamespace(name string) (*types.Namespace, error)

	// UpsertTrustedCluster creates or updates a TrustedCluster in the backend.
	UpsertTrustedCluster(ctx context.Context, tc types.TrustedCluster) (types.TrustedCluster, error)

	// GetTrustedCluster returns a single TrustedCluster by name.
	GetTrustedCluster(ctx context.Context, name string) (types.TrustedCluster, error)

	// GetTrustedClusters returns all TrustedClusters in the backend.
	GetTrustedClusters(ctx context.Context) ([]types.TrustedCluster, error)

	// DeleteTrustedCluster removes a TrustedCluster from the backend by name.
	DeleteTrustedCluster(ctx context.Context, name string) error

	// UpsertTunnelConnection upserts tunnel connection
	UpsertTunnelConnection(types.TunnelConnection) error

	// GetAllTunnelConnections returns all tunnel connections
	GetAllTunnelConnections(opts ...MarshalOption) ([]types.TunnelConnection, error)

	// DeleteTunnelConnection deletes tunnel connection by name
	DeleteTunnelConnection(clusterName string, connName string) error

	// GetRemoteClusters returns a list of remote clusters
	GetRemoteClusters(opts ...MarshalOption) ([]types.RemoteCluster, error)

	// GetRemoteCluster returns a remote cluster by name
	GetRemoteCluster(clusterName string) (types.RemoteCluster, error)

	// KeepAliveServer updates TTL of the server resource in the backend.
	KeepAliveServer(ctx context.Context, h types.KeepAlive) error

	// ListResoures returns a paginated list of resources.
	ListResources(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error)
}
