/*
Copyright 2020 Gravitational, Inc.

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

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// Get returns the web token described with req.
func (r *webTokens) Get(ctx context.Context, req types.GetWebTokenRequest) (types.WebToken, error) {
	if err := req.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	item, err := r.backend.Get(ctx, webTokenKey(req.Token))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	token, err := services.UnmarshalWebToken(item.Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return token, nil
}

// List gets all web tokens.
func (r *webTokens) List(ctx context.Context) (out []types.WebToken, err error) {
	key := backend.Key(webPrefix, tokensPrefix)
	result, err := r.backend.GetRange(ctx, key, backend.RangeEnd(key), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, item := range result.Items {
		token, err := services.UnmarshalWebToken(item.Value)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, token)
	}
	return out, nil
}

// Upsert updates the existing or inserts a new web token.
func (r *webTokens) Upsert(ctx context.Context, token types.WebToken) error {
	bytes, err := services.MarshalWebToken(token, services.WithVersion(types.V3))
	if err != nil {
		return trace.Wrap(err)
	}
	metadata := token.GetMetadata()
	item := backend.Item{
		Key:     webTokenKey(token.GetToken()),
		Value:   bytes,
		Expires: metadata.Expiry(),
	}
	_, err = r.backend.Put(ctx, item)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// Delete deletes the web token specified with req from the storage.
func (r *webTokens) Delete(ctx context.Context, req types.DeleteWebTokenRequest) error {
	if err := req.Check(); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(r.backend.Delete(ctx, webTokenKey(req.Token)))
}

// DeleteAll removes all web tokens.
func (r *webTokens) DeleteAll(ctx context.Context) error {
	startKey := backend.Key(webPrefix, tokensPrefix)
	if err := r.backend.DeleteRange(ctx, startKey, backend.RangeEnd(startKey)); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

type webTokens struct {
	backend backend.Backend
	log     logrus.FieldLogger
}

func webTokenKey(token string) (key []byte) {
	return backend.Key(webPrefix, tokensPrefix, token)
}
