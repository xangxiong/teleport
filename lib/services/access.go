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

	"github.com/gravitational/teleport/api/types"
)

// LockGetter is a service that gets locks.
type LockGetter interface {
	// GetLock gets a lock by name.
	GetLock(ctx context.Context, name string) (types.Lock, error)
	// GetLocks gets all/in-force locks that match at least one of the targets when specified.
	GetLocks(ctx context.Context, inForceOnly bool, targets ...types.LockTarget) ([]types.Lock, error)
}

// Access service manages roles and permissions.
type Access interface {
	// GetRoles returns a list of roles.
	GetRoles(ctx context.Context) ([]types.Role, error)
	// GetRole returns role by name.
	GetRole(ctx context.Context, name string) (types.Role, error)

	LockGetter
}
