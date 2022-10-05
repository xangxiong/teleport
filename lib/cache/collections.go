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
