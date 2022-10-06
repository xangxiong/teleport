/*
Copyright 2019 Gravitational, Inc.

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
	"bytes"
	"context"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// DynamicAccessService manages dynamic RBAC
type DynamicAccessService struct {
	backend.Backend
}

// NewDynamicAccessService returns new dynamic access service instance
func NewDynamicAccessService(backend backend.Backend) *DynamicAccessService {
	return &DynamicAccessService{Backend: backend}
}

func (s *DynamicAccessService) GetAccessRequest(ctx context.Context, name string) (types.AccessRequest, error) {
	item, err := s.Get(ctx, accessRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("access request %q not found", name)
		}
		return nil, trace.Wrap(err)
	}
	req, err := itemToAccessRequest(*item)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func (s *DynamicAccessService) getAccessRequestPluginData(ctx context.Context, filter types.PluginDataFilter) ([]types.PluginData, error) {
	// Filters which specify Resource are a special case since they will match exactly zero or one
	// possible PluginData instances.
	if filter.Resource != "" {
		item, err := s.Get(ctx, pluginDataKey(types.KindAccessRequest, filter.Resource))
		if err != nil {
			// A filter with zero matches is still a success, it just
			// happens to return an empty slice.
			if trace.IsNotFound(err) {
				return nil, nil
			}
			return nil, trace.Wrap(err)
		}
		data, err := itemToPluginData(*item)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !filter.Match(data) {
			// A filter with zero matches is still a success, it just
			// happens to return an empty slice.
			return nil, nil
		}
		return []types.PluginData{data}, nil
	}
	prefix := backend.Key(pluginDataPrefix, types.KindAccessRequest)
	result, err := s.GetRange(ctx, prefix, backend.RangeEnd(prefix), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var matches []types.PluginData
	for _, item := range result.Items {
		if !bytes.HasSuffix(item.Key, []byte(paramsPrefix)) {
			// Item represents a different resource type in the
			// same namespace.
			continue
		}
		data, err := itemToPluginData(item)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !filter.Match(data) {
			continue
		}
		matches = append(matches, data)
	}
	return matches, nil
}

// UpdatePluginData updates a per-resource PluginData entry.
func (s *DynamicAccessService) UpdatePluginData(ctx context.Context, params types.PluginDataUpdateParams) error {
	switch params.Kind {
	case types.KindAccessRequest:
		return trace.Wrap(s.updateAccessRequestPluginData(ctx, params))
	default:
		return trace.BadParameter("unsupported resource kind %q", params.Kind)
	}
}

func (s *DynamicAccessService) updateAccessRequestPluginData(ctx context.Context, params types.PluginDataUpdateParams) error {
	retryPeriod := retryPeriodMs * time.Millisecond
	retry, err := utils.NewLinear(utils.LinearConfig{
		Step: retryPeriod / 7,
		Max:  retryPeriod,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	// Update is attempted multiple times in the event of concurrent writes.
	for i := 0; i < maxCmpAttempts; i++ {
		var create bool
		var data types.PluginData
		item, err := s.Get(ctx, pluginDataKey(types.KindAccessRequest, params.Resource))
		if err == nil {
			data, err = itemToPluginData(*item)
			if err != nil {
				return trace.Wrap(err)
			}
			create = false
		} else {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
			// In order to prevent orphaned plugin data, we automatically
			// configure new instances to expire shortly after the AccessRequest
			// to which they are associated.  This discrepency in expiry gives
			// plugins the ability to use stored data when handling an expiry
			// (OpDelete) event.
			req, err := s.GetAccessRequest(ctx, params.Resource)
			if err != nil {
				return trace.Wrap(err)
			}
			data, err = types.NewPluginData(params.Resource, types.KindAccessRequest)
			if err != nil {
				return trace.Wrap(err)
			}
			data.SetExpiry(req.GetAccessExpiry().Add(time.Hour))
			create = true
		}
		if err := data.Update(params); err != nil {
			return trace.Wrap(err)
		}
		if err := data.CheckAndSetDefaults(); err != nil {
			return trace.Wrap(err)
		}
		newItem, err := itemFromPluginData(data)
		if err != nil {
			return trace.Wrap(err)
		}
		if create {
			if _, err := s.Create(ctx, newItem); err != nil {
				if trace.IsAlreadyExists(err) {
					select {
					case <-retry.After():
						retry.Inc()
						continue
					case <-ctx.Done():
						return trace.Wrap(ctx.Err())
					}
				}
				return trace.Wrap(err)
			}
		} else {
			if _, err := s.CompareAndSwap(ctx, *item, newItem); err != nil {
				if trace.IsCompareFailed(err) {
					select {
					case <-retry.After():
						retry.Inc()
						continue
					case <-ctx.Done():
						return trace.Wrap(ctx.Err())
					}
				}
				return trace.Wrap(err)
			}
		}
		return nil
	}
	return trace.CompareFailed("too many concurrent writes to plugin data %s", params.Resource)
}

func itemFromAccessRequest(req types.AccessRequest) (backend.Item, error) {
	value, err := services.MarshalAccessRequest(req)
	if err != nil {
		return backend.Item{}, trace.Wrap(err)
	}
	return backend.Item{
		Key:     accessRequestKey(req.GetName()),
		Value:   value,
		Expires: req.Expiry(),
		ID:      req.GetResourceID(),
	}, nil
}

func itemToAccessRequest(item backend.Item, opts ...services.MarshalOption) (types.AccessRequest, error) {
	opts = append(
		opts,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	req, err := services.UnmarshalAccessRequest(
		item.Value,
		opts...,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func itemFromPluginData(data types.PluginData) (backend.Item, error) {
	value, err := services.MarshalPluginData(data)
	if err != nil {
		return backend.Item{}, trace.Wrap(err)
	}
	// enforce explicit limit on resource size in order to prevent PluginData from
	// growing uncontrollably.
	if len(value) > teleport.MaxResourceSize {
		return backend.Item{}, trace.BadParameter("plugin data size limit exceeded")
	}
	return backend.Item{
		Key:     pluginDataKey(data.GetSubKind(), data.GetName()),
		Value:   value,
		Expires: data.Expiry(),
		ID:      data.GetResourceID(),
	}, nil
}

func itemToPluginData(item backend.Item) (types.PluginData, error) {
	data, err := services.UnmarshalPluginData(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return data, nil
}

func accessRequestKey(name string) []byte {
	return backend.Key(accessRequestsPrefix, name, paramsPrefix)
}

func pluginDataKey(kind string, name string) []byte {
	return backend.Key(pluginDataPrefix, kind, name, paramsPrefix)
}

const (
	accessRequestsPrefix = "access_requests"
	pluginDataPrefix     = "plugin_data"
	maxCmpAttempts       = 7
	retryPeriodMs        = 2048
)
