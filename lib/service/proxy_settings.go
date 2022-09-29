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

package service

import (
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"
)

// proxySettings is a helper type that allows to fetch the current proxy configuration.
type proxySettings struct {
	// cfg is the Teleport service configuration.
	cfg *Config
	// proxySSHAddr is the address of the proxy ssh service. It can be assigned during runtime when a user set the
	// proxy listener address to a random port (e.g. `127.0.0.1:0`).
	proxySSHAddr utils.NetAddr
	// accessPoint is the caching client connected to the auth server.
	accessPoint auth.ProxyAccessPoint
}
