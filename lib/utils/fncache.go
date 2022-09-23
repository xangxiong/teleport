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

package utils

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// NOTE: when making changes to this file, run tests with `TEST_FNCACHE_FUZZY=yes` to enable
// additional fuzzy tests which aren't run during normal CI.

var (
	// ErrFnCacheClosed is returned from Get when the FnCache context is closed
	ErrFnCacheClosed = errors.New("fncache permanently closed")
)

// FnCache is a helper for temporarily storing the results of regularly called functions. This helper is
// used to limit the amount of backend reads that occur while the primary cache is unhealthy.  Most resources
// do not require this treatment, but certain resources (cas, nodes, etc) can be loaded on a per-request
// basis and can cause significant numbers of backend reads if the cache is unhealthy or taking a while to init.
type FnCache struct {
	cfg         FnCacheConfig
	mu          sync.Mutex
	nextCleanup time.Time
	entries     map[any]*fnCacheEntry
}

// cleanupMultiplier is an arbitrary multiplier used to derive the default interval
// for periodic lazy cleanup of expired entries. This cache is typically used to
// store a small number of regularly read keys, so most old values aught to be
// removed upon subsequent reads of the same key. If the cache is being used in a
// context where keys might become regularly orphaned (no longer read), then a
// custom CleanupInterval should be provided.
const cleanupMultiplier time.Duration = 16

type FnCacheConfig struct {
	// TTL is the time to live for cache entries.
	TTL time.Duration
	// Clock is the clock used to determine the current time.
	Clock clockwork.Clock
	// Context is the context used to cancel the cache. All loadfns
	// will be provided this context.
	Context context.Context
	// ReloadOnErr causes entries to be reloaded immediately if
	// the currently loaded value is an error. Note that all concurrent
	// requests registered before load completes still observe the
	// same error. This option is only really useful for longer TTLs.
	ReloadOnErr bool
	// CleanupInterval is the interval at which cleanups occur (defaults to
	// 16x the supplied TTL). Longer cleanup intervals are appropriate for
	// caches where keys are unlikely to become orphaned. Shorter cleanup
	// intervals should be used when keys regularly become orphaned.
	CleanupInterval time.Duration
}

func (c *FnCacheConfig) CheckAndSetDefaults() error {
	if c.TTL <= 0 {
		return trace.BadParameter("missing TTL parameter")
	}

	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}

	if c.Context == nil {
		c.Context = context.Background()
	}

	if c.CleanupInterval <= 0 {
		c.CleanupInterval = c.TTL * cleanupMultiplier
	}

	return nil
}

func NewFnCache(cfg FnCacheConfig) (*FnCache, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &FnCache{
		cfg:     cfg,
		entries: make(map[any]*fnCacheEntry),
	}, nil
}

type fnCacheEntry struct {
	v      any
	e      error
	t      time.Time
	loaded chan struct{}
}

func (c *FnCache) removeExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		select {
		case <-entry.loaded:
			if now.After(entry.t.Add(c.cfg.TTL)) {
				delete(c.entries, key)
			}
		default:
			// entry is still being loaded
		}
	}
}

// FnCacheGet loads the result associated with the supplied key.  If no result is currently stored, or the stored result
// was acquired >ttl ago, then loadfn is used to reload it.  Subsequent calls while the value is being loaded/reloaded
// block until the first call updates the entry.  Note that the supplied context can cancel the call to Get, but will
// not cancel loading.  The supplied loadfn should not be canceled just because the specific request happens to have
// been canceled.
func FnCacheGet[T any](ctx context.Context, cache *FnCache, key any, loadfn func(ctx context.Context) (T, error)) (T, error) {
	t, err := cache.get(ctx, key, func(ctx context.Context) (any, error) {
		return loadfn(ctx)
	})

	ret, ok := t.(T)
	switch {
	case err != nil:
		return ret, err
	case !ok:
		return ret, trace.BadParameter("value retrieved was %T, expected %T", t, ret)
	}

	return ret, err
}

// get loads the result associated with the supplied key.  If no result is currently stored, or the stored result
// was acquired >ttl ago, then loadfn is used to reload it.  Subsequent calls while the value is being loaded/reloaded
// block until the first call updates the entry.  Note that the supplied context can cancel the call to Get, but will
// not cancel loading.  The supplied loadfn should not be canceled just because the specific request happens to have
// been canceled.
func (c *FnCache) get(ctx context.Context, key any, loadfn func(ctx context.Context) (any, error)) (any, error) {
	select {
	case <-c.cfg.Context.Done():
		return nil, ErrFnCacheClosed
	default:
	}

	c.mu.Lock()

	now := c.cfg.Clock.Now()

	// check if we need to perform periodic cleanup
	if now.After(c.nextCleanup) {
		c.removeExpiredLocked(now)
		c.nextCleanup = now.Add(c.cfg.CleanupInterval)
	}

	entry := c.entries[key]

	needsReload := true

	if entry != nil {
		select {
		case <-entry.loaded:
			needsReload = now.After(entry.t.Add(c.cfg.TTL))
			if c.cfg.ReloadOnErr && entry.e != nil {
				needsReload = true
			}
		default:
			// reload is already in progress
			needsReload = false
		}
	}

	if needsReload {
		// insert a new entry with a new loaded channel.  this channel will
		// block subsequent reads, and serve as a memory barrier for the results.
		entry = &fnCacheEntry{
			loaded: make(chan struct{}),
		}
		c.entries[key] = entry
		go func() {
			// link the config context with the span from ctx, if one exists,
			// so that the loadfn can be traced appropriately.
			loadCtx := oteltrace.ContextWithSpan(c.cfg.Context, oteltrace.SpanFromContext(ctx))
			entry.v, entry.e = loadfn(loadCtx)
			entry.t = c.cfg.Clock.Now()
			close(entry.loaded)
		}()
	}

	c.mu.Unlock()

	// wait for result to be loaded (this is also a memory barrier)
	select {
	case <-entry.loaded:
		return entry.v, entry.e
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.cfg.Context.Done():
		return nil, ErrFnCacheClosed
	}
}
