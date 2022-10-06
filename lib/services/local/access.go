/*
Copyright 2016 Gravitational, Inc.

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
	"encoding/json"
	"sort"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
)

// AccessService manages roles
type AccessService struct {
	backend.Backend
}

// NewAccessService returns new access service instance
func NewAccessService(backend backend.Backend) *AccessService {
	return &AccessService{Backend: backend}
}

// GetRoles returns a list of roles registered with the local auth server
func (s *AccessService) GetRoles(ctx context.Context) ([]types.Role, error) {
	result, err := s.GetRange(ctx, backend.Key(rolesPrefix), backend.RangeEnd(backend.Key(rolesPrefix)), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	out := make([]types.Role, 0, len(result.Items))
	for _, item := range result.Items {
		role, err := services.UnmarshalRole(item.Value,
			services.WithResourceID(item.ID), services.WithExpires(item.Expires))
		if err != nil {
			// Try to get the role name for the error, it allows admins to take action
			// against the "bad" role.
			h := &types.ResourceHeader{}
			_ = json.Unmarshal(item.Value, h)
			return nil, trace.WrapWithMessage(err, "role %q", h.GetName())
		}
		out = append(out, role)
	}
	sort.Sort(services.SortedRoles(out))
	return out, nil
}

// GetRole returns a role by name
func (s *AccessService) GetRole(ctx context.Context, name string) (types.Role, error) {
	if name == "" {
		return nil, trace.BadParameter("missing role name")
	}
	item, err := s.Get(ctx, backend.Key(rolesPrefix, name, paramsPrefix))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("role %v is not found", name)
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalRole(item.Value,
		services.WithResourceID(item.ID), services.WithExpires(item.Expires))
}

// GetLock gets a lock by name.
func (s *AccessService) GetLock(ctx context.Context, name string) (types.Lock, error) {
	if name == "" {
		return nil, trace.BadParameter("missing lock name")
	}
	item, err := s.Get(ctx, backend.Key(locksPrefix, name))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("lock %q is not found", name)
		}
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalLock(item.Value, services.WithResourceID(item.ID), services.WithExpires(item.Expires))
}

// GetLocks gets all/in-force locks that match at least one of the targets when specified.
func (s *AccessService) GetLocks(ctx context.Context, inForceOnly bool, targets ...types.LockTarget) ([]types.Lock, error) {
	startKey := backend.Key(locksPrefix)
	result, err := s.GetRange(ctx, startKey, backend.RangeEnd(startKey), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	out := []types.Lock{}
	for _, item := range result.Items {
		lock, err := services.UnmarshalLock(item.Value, services.WithResourceID(item.ID), services.WithExpires(item.Expires))
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if inForceOnly && !lock.IsInForce(s.Clock().Now()) {
			continue
		}
		// If no targets specified, return all of the found/in-force locks.
		if len(targets) == 0 {
			out = append(out, lock)
			continue
		}
		// Otherwise, use the targets as filters.
		for _, target := range targets {
			if target.Match(lock) {
				out = append(out, lock)
				break
			}
		}
	}
	return out, nil
}

const (
	rolesPrefix  = "roles"
	paramsPrefix = "params"
	locksPrefix  = "locks"
)
