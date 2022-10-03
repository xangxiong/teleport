/*
Copyright 2015-2021 Gravitational, Inc.

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

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"
)

// ServerWithRoles is a wrapper around auth service
// methods that focuses on authorizing every request
type ServerWithRoles struct {
	authServer *Server
	sessions   session.Service
	alog       events.IAuditLog
	// context holds authorization context
	context Context
}

func (a *ServerWithRoles) GetDomainName(ctx context.Context) (string, error) {
	// anyone can read it, no harm in that
	return a.authServer.GetDomainName()
}

// RegisterUsingIAMMethod registers the caller using the IAM join method and
// returns signed certs to join the cluster.
//
// See (*Server).RegisterUsingIAMMethod for further documentation.
//
// This wrapper does not do any extra authz checks, as the register method has
// its own authz mechanism.
func (a *ServerWithRoles) RegisterUsingIAMMethod(ctx context.Context, challengeResponse client.RegisterChallengeResponseFunc) (*proto.Certs, error) {
	return nil, nil
}
