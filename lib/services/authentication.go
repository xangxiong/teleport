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

// Package types contains all types and logic required by the Teleport API.

package services

import (
	"encoding/json"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// UnmarshalAuthPreference unmarshals the AuthPreference resource from JSON.
func UnmarshalAuthPreference(bytes []byte, opts ...MarshalOption) (types.AuthPreference, error) {
	var authPreference types.AuthPreferenceV2

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := utils.FastUnmarshal(bytes, &authPreference); err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	if err := authPreference.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.ID != 0 {
		authPreference.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		authPreference.SetExpiry(cfg.Expires)
	}
	return &authPreference, nil
}

// MarshalAuthPreference marshals the AuthPreference resource to JSON.
func MarshalAuthPreference(c types.AuthPreference, opts ...MarshalOption) ([]byte, error) {
	if err := c.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return json.Marshal(c)
}
