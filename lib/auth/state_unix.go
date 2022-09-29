//go:build !windows
// +build !windows

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

package auth

import (
	"context"

	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/trace"
)

// NewProcessStorage returns a new instance of the process storage.
func NewProcessStorage(ctx context.Context, path string) (*ProcessStorage, error) {
	// if path == "" {
	// 	return nil, trace.BadParameter("missing parameter path")
	// }

	// litebk, err := lite.NewWithConfig(ctx, lite.Config{
	// 	Path:      path,
	// 	EventsOff: true,
	// 	Sync:      lite.SyncFull,
	// })
	// if err != nil {
	// 	return nil, trace.Wrap(err)
	// }

	// return &ProcessStorage{Backend: litebk}, nil

	// XXIONG: will use memory for linux as well to prevent clogging file system on small devices
	m, err := memory.New(memory.Config{
		Context:   ctx,
		EventsOff: true,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &ProcessStorage{Backend: m}, nil
}
