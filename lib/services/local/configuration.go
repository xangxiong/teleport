/*
Copyright 2017 Gravitational, Inc.

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

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
)

// ClusterConfigurationService is responsible for managing cluster configuration.
type ClusterConfigurationService struct {
	backend.Backend
}

// NewClusterConfigurationService returns a new ClusterConfigurationService.
func NewClusterConfigurationService(backend backend.Backend) (*ClusterConfigurationService, error) {
	return &ClusterConfigurationService{
		Backend: backend,
	}, nil
}

// GetClusterName gets the name of the cluster from the backend.
func (s *ClusterConfigurationService) GetClusterName(opts ...services.MarshalOption) (types.ClusterName, error) {
	item, err := s.Get(context.TODO(), backend.Key(clusterConfigPrefix, namePrefix))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("cluster name not found")
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalClusterName(item.Value,
		services.AddOptions(opts, services.WithResourceID(item.ID))...)
}

// GetStaticTokens gets the list of static tokens used to provision nodes.
func (s *ClusterConfigurationService) GetStaticTokens() (types.StaticTokens, error) {
	item, err := s.Get(context.TODO(), backend.Key(clusterConfigPrefix, staticTokensPrefix))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("static tokens not found")
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalStaticTokens(item.Value,
		services.WithResourceID(item.ID), services.WithExpires(item.Expires))
}

// GetAuthPreference fetches the cluster authentication preferences
// from the backend and return them.
func (s *ClusterConfigurationService) GetAuthPreference(ctx context.Context) (types.AuthPreference, error) {
	item, err := s.Get(ctx, backend.Key(authPrefix, preferencePrefix, generalPrefix))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("authentication preference not found")
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalAuthPreference(item.Value,
		services.WithResourceID(item.ID), services.WithExpires(item.Expires))
}

// GetClusterNetworkingConfig gets cluster networking config from the backend.
func (s *ClusterConfigurationService) GetClusterNetworkingConfig(ctx context.Context, opts ...services.MarshalOption) (types.ClusterNetworkingConfig, error) {
	item, err := s.Get(ctx, backend.Key(clusterConfigPrefix, networkingPrefix))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("cluster networking config not found")
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalClusterNetworkingConfig(item.Value, append(opts, services.WithResourceID(item.ID), services.WithExpires(item.Expires))...)
}

const (
	clusterConfigPrefix    = "cluster_configuration"
	namePrefix             = "name"
	staticTokensPrefix     = "static_tokens"
	authPrefix             = "authentication"
	preferencePrefix       = "preference"
	generalPrefix          = "general"
	auditPrefix            = "audit"
	networkingPrefix       = "networking"
	sessionRecordingPrefix = "session_recording"
)
