/*
Copyright 2017-2021 Gravitational, Inc.

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
	"time"
)

// createUserParams is a set of parameters used to create a user for an
// external identity provider.
type createUserParams struct {
	// connectorName is the name of the connector for the identity provider.
	connectorName string

	// username is the Teleport user name .
	username string

	// roles is the list of roles this user is assigned to.
	roles []string

	// traits is the list of traits for this user.
	traits map[string][]string

	// sessionTTL is how long this session will last.
	sessionTTL time.Duration
}
