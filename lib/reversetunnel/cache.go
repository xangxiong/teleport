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

package reversetunnel

import (
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/sshca"

	"github.com/gravitational/trace"
	"github.com/gravitational/ttlmap"
)

type certificateCache struct {
	cache      *ttlmap.TTLMap
	authClient auth.ClientI
	keygen     sshca.Authority
}

// newHostCertificateCache creates a shared host certificate cache that is
// used by the forwarding server.
func newHostCertificateCache(keygen sshca.Authority, authClient auth.ClientI) (*certificateCache, error) {
	native.PrecomputeKeys() // ensure native package is set to precompute keys
	cache, err := ttlmap.New(defaults.HostCertCacheSize)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &certificateCache{
		keygen:     keygen,
		cache:      cache,
		authClient: authClient,
	}, nil
}
