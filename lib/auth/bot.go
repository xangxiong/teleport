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

package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
)

// BotResourceName returns the default name for resources associated with the
// given named bot.
func BotResourceName(botName string) string {
	return "bot-" + strings.ReplaceAll(botName, " ", "-")
}

// createBotRole creates a role from a bot template with the given parameters.
func createBotRole(ctx context.Context, s *Server, botName string, resourceName string, roleRequests []string) (types.Role, error) {
	role, err := types.NewRole(resourceName, types.RoleSpecV5{
		Options: types.RoleOptions{
			// TODO: inherit TTLs from cert length?
			MaxSessionTTL: types.Duration(12 * time.Hour),
		},
		Allow: types.RoleConditions{
			Rules: []types.Rule{
				// Bots read certificate authorities to watch for CA rotations
				types.NewRule(types.KindCertAuthority, []string{types.VerbReadNoSecrets}),
			},
			Impersonate: &types.ImpersonateConditions{
				Roles: roleRequests,
			},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	meta := role.GetMetadata()
	meta.Description = fmt.Sprintf("Automatically generated role for bot %s", botName)
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	meta.Labels[types.BotLabel] = botName
	role.SetMetadata(meta)

	err = s.CreateRole(ctx, role)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return role, nil
}

// deleteBotRole removes an existing bot role, ensuring that it has bot labels
// matching the bot before deleting anything.
func (s *Server) deleteBotRole(ctx context.Context, botName, resourceName string) error {
	role, err := s.GetRole(ctx, resourceName)
	if err != nil {
		return trace.Wrap(err, "could not fetch expected bot role %s", resourceName)
	}

	label, ok := role.GetMetadata().Labels[types.BotLabel]
	if !ok {
		err = trace.Errorf("will not delete role %s that is missing label %s; delete the role manually if desired", resourceName, types.BotLabel)
	} else if label != botName {
		err = trace.Errorf("will not delete role %s with mismatched label %s = %s", resourceName, types.BotLabel, label)
	} else {
		err = s.DeleteRole(ctx, resourceName)
	}

	return err
}

// checkOrCreateBotToken checks the existing token if given, or creates a new
// random dynamic provision token which allows bots to join with the given
// botName. Returns the token and any error.
func (s *Server) checkOrCreateBotToken(ctx context.Context, req *proto.CreateBotRequest) (types.ProvisionToken, error) {
	botName := req.Name

	// if the request includes a TokenID it should already exist
	if req.TokenID != "" {
		provisionToken, err := s.GetToken(ctx, req.TokenID)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, trace.NotFound("token with name %q not found, create the token or do not set TokenName: %v",
					req.TokenID, err)
			}
			return nil, trace.Wrap(err)
		}
		if !provisionToken.GetRoles().Include(types.RoleBot) {
			return nil, trace.BadParameter("token %q is not valid for role %q",
				req.TokenID, types.RoleBot)
		}
		if provisionToken.GetBotName() != botName {
			return nil, trace.BadParameter("token %q is valid for bot with name %q, not %q",
				req.TokenID, provisionToken.GetBotName(), botName)
		}
		switch provisionToken.GetJoinMethod() {
		case types.JoinMethodToken:
		default:
			return nil, trace.BadParameter(
				"token %q has join method %q which is not supported for bots. Supported join methods are %v",
				req.TokenID, provisionToken.GetJoinMethod(), []types.JoinMethod{types.JoinMethodToken})
		}
		return provisionToken, nil
	}

	// create a new random dynamic token
	tokenName, err := utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ttl := time.Duration(req.TTL)
	if ttl == 0 {
		ttl = defaults.DefaultBotJoinTTL
	}

	tokenSpec := types.ProvisionTokenSpecV2{
		Roles:      types.SystemRoles{types.RoleBot},
		JoinMethod: types.JoinMethodToken,
		BotName:    botName,
	}
	token, err := types.NewProvisionTokenFromSpec(tokenName, time.Now().Add(ttl), tokenSpec)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.UpsertToken(ctx, token); err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: audit log event

	return token, nil
}
