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
	"context"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
)

// CreateResources attempts to dynamically create the supplied resources.
// This function returns `trace.AlreadyExistsError` if one or more resources
// would be overwritten, and `trace.NotImplementedError` if any resources
// are of an unsupported type (see `ItemsFromResources(...)`).
//
// NOTE: This function is non-atomic and performs no internal synchronization;
// backend must be locked by caller when operating in parallel environment.
func CreateResources(ctx context.Context, b backend.Backend, resources ...types.Resource) error {
	items, err := ItemsFromResources(resources...)
	if err != nil {
		return trace.Wrap(err)
	}
	// ensure all items do not exist before continuing.
	for _, item := range items {
		_, err = b.Get(ctx, item.Key)
		if !trace.IsNotFound(err) {
			if err != nil {
				return trace.Wrap(err)
			}
			return trace.AlreadyExists("resource %q already exists", string(item.Key))
		}
	}
	// create all items.
	for _, item := range items {
		_, err := b.Create(ctx, item)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// ItemsFromResources attempts to convert resources into instances of backend.Item.
// NOTE: this is not necessarily a 1-to-1 conversion.
func ItemsFromResources(resources ...types.Resource) ([]backend.Item, error) {
	var allItems []backend.Item
	for _, rsc := range resources {
		items, err := itemsFromResource(rsc)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		allItems = append(allItems, items...)
	}
	return allItems, nil
}

// ItemsFromResource attempts to construct one or more instances of `backend.Item` from
// a given resource.  If `rsc` is not one of the supported resource types,
// a `trace.NotImplementedError` is returned.
func itemsFromResource(resource types.Resource) ([]backend.Item, error) {
	var item *backend.Item
	var extItems []backend.Item
	var err error
	switch r := resource.(type) {
	case types.CertAuthority:
		item, err = itemFromCertAuthority(r)
	default:
		return nil, trace.NotImplemented("cannot itemFrom resource of type %T", resource)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]backend.Item, 0, len(extItems)+1)
	items = append(items, *item)
	items = append(items, extItems...)
	return items, nil
}

// ItemsToResources converts one or more items into one or more resources.
// NOTE: This is not necessarily a 1-to-1 conversion, and order is not preserved.
func ItemsToResources(items ...backend.Item) ([]types.Resource, error) {
	var resources []types.Resource
	return resources, nil
}

// itemFromCertAuthority attempts to encode the supplied certificate authority
// as an instance of `backend.Item` suitable for storage.
func itemFromCertAuthority(ca types.CertAuthority) (*backend.Item, error) {
	if err := services.ValidateCertAuthority(ca); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.MarshalCertAuthority(ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(authoritiesPrefix, string(ca.GetType()), ca.GetName()),
		Value:   value,
		Expires: ca.Expiry(),
		ID:      ca.GetResourceID(),
	}
	return item, nil
}
