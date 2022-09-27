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

package clusters

import (
	"context"
	"errors"
	"sort"

	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/lib/auth"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
	"github.com/gravitational/teleport/lib/client"
	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"

	"github.com/gravitational/trace"
)

// SyncAuthPreference fetches Teleport auth preferences and stores it in the cluster profile
func (c *Cluster) SyncAuthPreference(ctx context.Context) (*webclient.WebConfigAuthSettings, error) {
	_, err := c.clusterClient.Ping(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := c.clusterClient.SaveProfile(c.dir, false); err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := c.clusterClient.GetWebConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &cfg.Auth, nil
}

// Logout deletes all cluster certificates
func (c *Cluster) Logout(ctx context.Context) error {
	// // Delete db certs
	// for _, db := range c.status.Databases {
	// 	err := dbprofile.Delete(c.clusterClient, db)
	// 	if err != nil {
	// 		return trace.Wrap(err)
	// 	}
	// }

	// Get the address of the active Kubernetes proxy to find AuthInfos,
	// Clusters, and Contexts in kubeconfig.
	// clusterName, _ := c.clusterClient.KubeProxyHostPort()
	// if c.clusterClient.SiteName != "" {
	// 	clusterName = fmt.Sprintf("%v.%v", c.clusterClient.SiteName, clusterName)
	// }

	// Remove cluster entries from kubeconfig
	// if err := kubeconfig.Remove("", clusterName); err != nil {
	// 	return trace.Wrap(err)
	// }

	// Remove keys for this user from disk and running agent.
	if err := c.clusterClient.Logout(); !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	return nil
}

// LocalLogin processes local logins for this cluster
func (c *Cluster) LocalLogin(ctx context.Context, user, password, otpToken string) error {
	pingResp, err := c.clusterClient.Ping(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO(alex-kovoy): SiteName needs to be reset if trying to login to a cluster with
	// existing profile for the first time (investigate why)
	c.clusterClient.SiteName = ""

	switch pingResp.Auth.SecondFactor {
	case constants.SecondFactorOff, constants.SecondFactorOTP:
		err := c.localLogin(ctx, user, password, otpToken)
		if err != nil {
			return trace.Wrap(err)
		}
	case constants.SecondFactorU2F, constants.SecondFactorWebauthn:
		err := c.localMFALogin(ctx, user, password)
		if err != nil {
			return trace.Wrap(err)
		}
	case constants.SecondFactorOn, constants.SecondFactorOptional:
		var err error

		// tsh always uses client.SSHAgentMFALogin for any `second_factor` option other than `off` and
		// `otp`. If it's set to `on` or `optional` and it turns out the user wants to use an OTP, it
		// bails out to stdin to ask them for it.
		//
		// Connect cannot do that, but it still wants to use the auth code from lib/client that it
		// shares with tsh. So to temporarily work around this problem, we check if the OTP token was
		// submitted. If yes, then we use client.SSHAgentLogin, which lets us provide the token and skip
		// asking for it over stdin. If not, we use client.SSHAgentMFALogin which should handle auth
		// methods that don't use OTP.
		if otpToken != "" {
			err = c.localLogin(ctx, user, password, otpToken)
		} else {
			err = c.localMFALogin(ctx, user, password)
		}

		if err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.BadParameter("unsupported second factor type: %q", pingResp.Auth.SecondFactor)
	}

	return nil
}

// SSOLogin logs in a user to the Teleport cluster using supported SSO provider
func (c *Cluster) SSOLogin(ctx context.Context, providerType, providerName string) error {
	if _, err := c.clusterClient.Ping(ctx); err != nil {
		return trace.Wrap(err)
	}

	key, err := client.GenerateRSAKey()
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO(alex-kovoy): SiteName needs to be reset if trying to login to a cluster with
	// existing profile for the first time (investigate why)
	c.clusterClient.SiteName = ""

	response, err := client.SSHAgentSSOLogin(ctx, client.SSHLoginSSO{
		SSHLogin: client.SSHLogin{
			ProxyAddr:     c.clusterClient.WebProxyAddr,
			PubKey:        key.MarshalSSHPublicKey(),
			TTL:           c.clusterClient.KeyTTL,
			Insecure:      c.clusterClient.InsecureSkipVerify,
			Compatibility: c.clusterClient.CertificateFormat,
			// KubernetesCluster: c.clusterClient.KubernetesCluster,
		},
		ConnectorID: providerName,
		Protocol:    providerType,
		BindAddr:    c.clusterClient.BindAddr,
		Browser:     c.clusterClient.Browser,
	}, nil)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := c.processAuthResponse(ctx, key, response); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (c *Cluster) localMFALogin(ctx context.Context, user, password string) error {
	key, err := client.GenerateRSAKey()
	if err != nil {
		return trace.Wrap(err)
	}

	response, err := client.SSHAgentMFALogin(ctx, client.SSHLoginMFA{
		SSHLogin: client.SSHLogin{
			ProxyAddr:      c.clusterClient.WebProxyAddr,
			PubKey:         key.MarshalSSHPublicKey(),
			TTL:            c.clusterClient.KeyTTL,
			Insecure:       c.clusterClient.InsecureSkipVerify,
			Compatibility:  c.clusterClient.CertificateFormat,
			RouteToCluster: c.clusterClient.SiteName,
			// KubernetesCluster: c.clusterClient.KubernetesCluster,
		},
		User:     user,
		Password: password,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if err := c.processAuthResponse(ctx, key, response); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (c *Cluster) localLogin(ctx context.Context, user, password, otpToken string) error {
	key, err := client.GenerateRSAKey()
	if err != nil {
		return trace.Wrap(err)
	}

	response, err := client.SSHAgentLogin(ctx, client.SSHLoginDirect{
		SSHLogin: client.SSHLogin{
			ProxyAddr:     c.clusterClient.WebProxyAddr,
			PubKey:        key.MarshalSSHPublicKey(),
			TTL:           c.clusterClient.KeyTTL,
			Insecure:      c.clusterClient.InsecureSkipVerify,
			Compatibility: c.clusterClient.CertificateFormat,
			// KubernetesCluster: c.clusterClient.KubernetesCluster,
		},
		User:     user,
		Password: password,
		OTPToken: otpToken,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if err := c.processAuthResponse(ctx, key, response); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (c *Cluster) processAuthResponse(ctx context.Context, key *client.Key, response *auth.SSHLoginResponse) error {
	// Check that a host certificate for at least one cluster was returned.
	if len(response.HostSigners) == 0 {
		return trace.BadParameter("bad response from the server: expected at least one certificate, got 0")
	}

	// extract the new certificate out of the response
	key.Cert = response.Cert
	key.TLSCert = response.TLSCert
	key.TrustedCA = response.HostSigners
	key.Username = response.Username

	// if c.clusterClient.KubernetesCluster != "" {
	// 	key.KubeTLSCerts[c.clusterClient.KubernetesCluster] = response.TLSCert
	// }
	// if c.clusterClient.DatabaseService != "" {
	// 	key.DBTLSCerts[c.clusterClient.DatabaseService] = response.TLSCert
	// }

	// Store the requested cluster name in the key.
	key.ClusterName = c.clusterClient.SiteName
	if key.ClusterName == "" {
		rootClusterName := key.TrustedCA[0].ClusterName
		key.ClusterName = rootClusterName
		c.clusterClient.SiteName = rootClusterName
	}

	// Update username before updating the profile
	c.clusterClient.LocalAgent().UpdateUsername(response.Username)
	c.clusterClient.Username = response.Username

	if err := c.clusterClient.ActivateKey(ctx, key); err != nil {
		return trace.Wrap(err)
	}

	if err := c.clusterClient.SaveProfile(c.dir, true); err != nil {
		return trace.Wrap(err)
	}

	status, err := client.ReadProfileStatus(c.dir, key.ProxyHost)
	if err != nil {
		return trace.Wrap(err)
	}

	c.status = *status

	return nil
}

// PasswordlessLogin processes passwordless logins for this cluster.
func (c *Cluster) PasswordlessLogin(ctx context.Context, stream api.TerminalService_LoginPasswordlessServer) error {
	if _, err := c.clusterClient.Ping(ctx); err != nil {
		return trace.Wrap(err)
	}

	key, err := client.GenerateRSAKey()
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO(alex-kovoy): SiteName needs to be reset if trying to login to a cluster with
	// existing profile for the first time (investigate why)
	c.clusterClient.SiteName = ""

	response, err := client.SSHAgentPasswordlessLogin(ctx, client.SSHLoginPasswordless{
		SSHLogin: client.SSHLogin{
			ProxyAddr:      c.clusterClient.WebProxyAddr,
			PubKey:         key.MarshalSSHPublicKey(),
			TTL:            c.clusterClient.KeyTTL,
			Insecure:       c.clusterClient.InsecureSkipVerify,
			Compatibility:  c.clusterClient.CertificateFormat,
			RouteToCluster: c.clusterClient.SiteName,
			// KubernetesCluster: c.clusterClient.KubernetesCluster,
		},
		AuthenticatorAttachment: c.clusterClient.AuthenticatorAttachment,
		CustomPrompt:            newPwdlessLoginPrompt(ctx, stream),
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if err := c.processAuthResponse(ctx, key, response); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// pwdlessLoginPrompt is a implementation for wancli.LoginPrompt for teleterm passwordless logins.
type pwdlessLoginPrompt struct {
	Stream api.TerminalService_LoginPasswordlessServer
}

func newPwdlessLoginPrompt(ctx context.Context, stream api.TerminalService_LoginPasswordlessServer) *pwdlessLoginPrompt {
	return &pwdlessLoginPrompt{
		Stream: stream,
	}
}

// PromptPIN prompts the user for a PIN.
func (p *pwdlessLoginPrompt) PromptPIN() (string, error) {
	if err := p.Stream.Send(&api.LoginPasswordlessResponse{
		Prompt: api.PasswordlessPrompt_PASSWORDLESS_PROMPT_PIN,
	}); err != nil {
		return "", trace.Wrap(err)
	}

	req, err := p.Stream.Recv()
	if err != nil {
		return "", trace.Wrap(err)
	}

	pinRes := req.GetPin()
	if pinRes == nil || pinRes.GetPin() == "" {
		return "", trace.BadParameter("pin is required")
	}

	return pinRes.GetPin(), nil
}

// PromptTouch prompts the user for a security key touch.
func (p *pwdlessLoginPrompt) PromptTouch() error {
	return trace.Wrap(p.Stream.Send(&api.LoginPasswordlessResponse{Prompt: api.PasswordlessPrompt_PASSWORDLESS_PROMPT_TAP}))
}

// PromptCredential prompts the user to select a login name in the list of logins.
func (p *pwdlessLoginPrompt) PromptCredential(deviceCreds []*wancli.CredentialInfo) (*wancli.CredentialInfo, error) {
	// Shouldn't happen, but let's check just in case.
	if len(deviceCreds) == 0 {
		return nil, errors.New("attempted to prompt credential with empty credentials")
	}

	// Sorts in place.
	sort.Slice(deviceCreds, func(i, j int) bool {
		c1 := deviceCreds[i]
		c2 := deviceCreds[j]
		return c1.User.Name < c2.User.Name
	})

	// Convert to grpc message.
	creds := make([]*api.CredentialInfo, len(deviceCreds))
	for i, cred := range deviceCreds {
		creds[i] = &api.CredentialInfo{
			Username: cred.User.Name,
		}
	}

	if err := p.Stream.Send(&api.LoginPasswordlessResponse{
		Prompt:      api.PasswordlessPrompt_PASSWORDLESS_PROMPT_CREDENTIAL,
		Credentials: creds,
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	req, err := p.Stream.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	credRes := req.GetCredential()
	if credRes == nil {
		return nil, trace.BadParameter("login name must be selected")
	}

	// Test for out of range index values.
	selectedIndex := credRes.GetIndex()
	if selectedIndex < 0 || selectedIndex > int64(len(creds))-1 {
		return nil, trace.BadParameter("invalid login name")
	}

	return deviceCreds[selectedIndex], nil
}
