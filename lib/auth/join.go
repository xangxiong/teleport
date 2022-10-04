/*
Copyright 2022 Gravitational, Inc.

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

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

// tokenJoinMethod returns the join method of the token with the given tokenName
func (a *Server) tokenJoinMethod(ctx context.Context, tokenName string) types.JoinMethod {
	provisionToken, err := a.GetToken(ctx, tokenName)
	if err != nil {
		// could not find dynamic token, assume static token. If it does not
		// exist this will be caught later.
		return types.JoinMethodToken
	}
	return provisionToken.GetJoinMethod()
}

func (a *Server) generateCerts(ctx context.Context, provisionToken types.ProvisionToken, req *types.RegisterUsingTokenRequest) (*proto.Certs, error) {
	// instance certs include an additional field that specifies the list of
	// all services authorized by the token.
	var systemRoles []types.SystemRole
	if req.Role == types.RoleInstance {
		for _, r := range provisionToken.GetRoles() {
			if r.IsLocalService() {
				systemRoles = append(systemRoles, r)
			} else {
				log.Warnf("Omitting non-service system role from instance cert: %q", r)
			}
		}
	}

	// generate and return host certificate and keys
	certs, err := a.GenerateHostCerts(ctx,
		&proto.HostCertsRequest{
			HostID:               req.HostID,
			NodeName:             req.NodeName,
			Role:                 req.Role,
			AdditionalPrincipals: req.AdditionalPrincipals,
			PublicTLSKey:         req.PublicTLSKey,
			PublicSSHKey:         req.PublicSSHKey,
			RemoteAddr:           req.RemoteAddr,
			DNSNames:             req.DNSNames,
			SystemRoles:          systemRoles,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.Infof("Node %q [%v] has joined the cluster.", req.NodeName, req.HostID)
	return certs, nil
}
