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

package backend

import (
	"context"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"

	"github.com/gravitational/trace"
	lru "github.com/hashicorp/golang-lru"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
)

const reporterDefaultCacheSize = 1000

// ReporterConfig configures reporter wrapper
type ReporterConfig struct {
	// Backend is a backend to wrap
	Backend Backend
	// Component is a component name to report
	Component string
	// Number of the most recent backend requests to preserve for top requests
	// metric. Higher value means higher memory usage but fewer infrequent
	// requests forgotten.
	TopRequestsCount int
}

// CheckAndSetDefaults checks and sets
func (r *ReporterConfig) CheckAndSetDefaults() error {
	if r.Backend == nil {
		return trace.BadParameter("missing parameter Backend")
	}
	if r.Component == "" {
		r.Component = teleport.ComponentBackend
	}
	if r.TopRequestsCount == 0 {
		r.TopRequestsCount = reporterDefaultCacheSize
	}
	return nil
}

// Reporter wraps a Backend implementation and reports
// statistics about the backend operations
type Reporter struct {
	// ReporterConfig contains reporter wrapper configuration
	ReporterConfig

	// topRequestsCache is an LRU cache to track the most frequent recent
	// backend keys. All keys in this cache map to existing labels in the
	// requests metric. Any evicted keys are also deleted from the metric.
	//
	// This will keep an upper limit on our memory usage while still always
	// reporting the most active keys.
	topRequestsCache *lru.Cache
}

// NewReporter returns a new Reporter.
func NewReporter(cfg ReporterConfig) (*Reporter, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	cache, err := lru.NewWithEvict(cfg.TopRequestsCount, func(key interface{}, value interface{}) {
		_, ok := key.(topRequestsCacheKey)
		if !ok {
			log.Errorf("BUG: invalid cache key type: %T", key)
			return
		}
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	r := &Reporter{
		ReporterConfig:   cfg,
		topRequestsCache: cache,
	}
	return r, nil
}

// GetRange returns query range
func (s *Reporter) GetRange(ctx context.Context, startKey []byte, endKey []byte, limit int) (*GetResult, error) {
	res, err := s.Backend.GetRange(ctx, startKey, endKey, limit)
	s.trackRequest(types.OpGet, startKey, endKey)
	return res, err
}

// Create creates item if it does not exist
func (s *Reporter) Create(ctx context.Context, i Item) (*Lease, error) {
	lease, err := s.Backend.Create(ctx, i)
	s.trackRequest(types.OpPut, i.Key, nil)
	return lease, err
}

// Put puts value into backend (creates if it does not
// exists, updates it otherwise)
func (s *Reporter) Put(ctx context.Context, i Item) (*Lease, error) {
	lease, err := s.Backend.Put(ctx, i)
	s.trackRequest(types.OpPut, i.Key, nil)
	return lease, err
}

// Update updates value in the backend
func (s *Reporter) Update(ctx context.Context, i Item) (*Lease, error) {
	lease, err := s.Backend.Update(ctx, i)
	s.trackRequest(types.OpPut, i.Key, nil)
	return lease, err
}

// Get returns a single item or not found error
func (s *Reporter) Get(ctx context.Context, key []byte) (*Item, error) {
	item, err := s.Backend.Get(ctx, key)
	s.trackRequest(types.OpGet, key, nil)
	return item, err
}

// CompareAndSwap compares item with existing item
// and replaces is with replaceWith item
func (s *Reporter) CompareAndSwap(ctx context.Context, expected Item, replaceWith Item) (*Lease, error) {
	lease, err := s.Backend.CompareAndSwap(ctx, expected, replaceWith)
	s.trackRequest(types.OpPut, expected.Key, nil)
	return lease, err
}

// Delete deletes item by key
func (s *Reporter) Delete(ctx context.Context, key []byte) error {
	err := s.Backend.Delete(ctx, key)
	s.trackRequest(types.OpDelete, key, nil)
	return err
}

// DeleteRange deletes range of items
func (s *Reporter) DeleteRange(ctx context.Context, startKey []byte, endKey []byte) error {
	err := s.Backend.DeleteRange(ctx, startKey, endKey)
	s.trackRequest(types.OpDelete, startKey, endKey)
	return err
}

// KeepAlive keeps object from expiring, updates lease on the existing object,
// expires contains the new expiry to set on the lease,
// some backends may ignore expires based on the implementation
// in case if the lease managed server side
func (s *Reporter) KeepAlive(ctx context.Context, lease Lease, expires time.Time) error {
	err := s.Backend.KeepAlive(ctx, lease, expires)
	s.trackRequest(types.OpPut, lease.Key, nil)
	return err
}

// Close releases the resources taken up by this backend
func (s *Reporter) Close() error {
	return s.Backend.Close()
}

// CloseWatchers closes all the watchers
// without closing the backend
func (s *Reporter) CloseWatchers() {
	s.Backend.CloseWatchers()
}

// Clock returns clock used by this backend
func (s *Reporter) Clock() clockwork.Clock {
	return s.Backend.Clock()
}

type topRequestsCacheKey struct {
	component string
	key       string
	isRange   string
}

// trackRequests tracks top requests, endKey is supplied for ranges
func (s *Reporter) trackRequest(opType types.OpType, key []byte, endKey []byte) {
	if len(key) == 0 {
		return
	}
	keyLabel := buildKeyLabel(string(key), sensitiveBackendPrefixes)
	rangeSuffix := teleport.TagFalse
	if len(endKey) != 0 {
		// Range denotes range queries in stat entry
		rangeSuffix = teleport.TagTrue
	}

	s.topRequestsCache.Add(topRequestsCacheKey{
		component: s.Component,
		key:       keyLabel,
		isRange:   rangeSuffix,
	}, struct{}{})
}

// buildKeyLabel builds the key label for storing to the backend. The key's name
// is masked if it is determined to be sensitive based on sensitivePrefixes.
func buildKeyLabel(key string, sensitivePrefixes []string) string {
	parts := strings.Split(key, string(Separator))
	if len(parts) > 3 {
		// Cut the key down to 3 parts, otherwise too many
		// distinct requests can end up in the key label map.
		parts = parts[:3]
	}

	// If the key matches "/sensitiveprefix/keyname", mask the key.
	if len(parts) == 3 && len(parts[0]) == 0 && apiutils.SliceContainsStr(sensitivePrefixes, parts[1]) {
		parts[2] = string(MaskKeyName(parts[2]))
	}

	return strings.Join(parts, string(Separator))
}

// sensitiveBackendPrefixes is a list of backend request prefixes preceding
// sensitive values.
var sensitiveBackendPrefixes = []string{
	"tokens",
	"resetpasswordtokens",
	"adduseru2fchallenges",
	"access_requests",
}

// ReporterWatcher is a wrapper around backend
// watcher that reports events
type ReporterWatcher struct {
	Watcher
	Component string
}
