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

package conntest

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	libsshutils "github.com/gravitational/teleport/lib/sshutils"
)

// SSHConnectionTesterConfig has the necessary fields to create a new SSHConnectionTester.
type SSHConnectionTesterConfig struct {
	// UserClient is an auth client that has a User's identity.
	// This is the user that is running the SSH Connection Test.
	UserClient auth.ClientI

	// ProxyHostPort is the proxy to use in the `--proxy` format (host:webPort,sshPort)
	ProxyHostPort string

	// TLSRoutingEnabled indicates that proxy supports ALPN SNI server where
	// all proxy services are exposed on a single TLS listener (Proxy Web Listener).
	TLSRoutingEnabled bool
}

// SSHConnectionTester implements the ConnectionTester interface for Testing SSH access
type SSHConnectionTester struct {
	cfg          SSHConnectionTesterConfig
	webProxyAddr string
	sshProxyAddr string
}

// NewSSHConnectionTester creates a new SSHConnectionTester
func NewSSHConnectionTester(cfg SSHConnectionTesterConfig) (*SSHConnectionTester, error) {
	parsedProxyHostAddr, err := client.ParseProxyHost(cfg.ProxyHostPort)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &SSHConnectionTester{
		cfg:          cfg,
		webProxyAddr: parsedProxyHostAddr.WebProxyAddr,
		sshProxyAddr: parsedProxyHostAddr.SSHProxyAddr,
	}, nil
}

func (s SSHConnectionTester) handleErrFromSSH(ctx context.Context, connectionDiagnosticID string, sshPrincipal string, sshError error, processStdout *bytes.Buffer) (types.ConnectionDiagnostic, error) {
	if trace.IsConnectionProblem(sshError) {
		connDiag, err := s.cfg.UserClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
			types.ConnectionDiagnosticTrace_CONNECTIVITY,
			`Failed to connect to the Node. Ensure teleport service is running using "systemctl status teleport".`,
			sshError,
		))
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connDiag, nil
	}

	processStdoutString := strings.TrimSpace(processStdout.String())
	if strings.HasPrefix(processStdoutString, "Failed to launch: user: unknown user") {
		connDiag, err := s.cfg.UserClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
			types.ConnectionDiagnosticTrace_NODE_PRINCIPAL,
			fmt.Sprintf("Invalid user. Please ensure the principal %q is a valid Linux login in the target node. Output from Node: %v", sshPrincipal, processStdoutString),
			sshError,
		))
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connDiag, nil
	}

	// This happens when the principal is not part of the allowed ones.
	// A trace was already added by the Node and, here, we just return the diagnostic.
	if trace.IsAccessDenied(sshError) {
		connDiag, err := s.cfg.UserClient.GetConnectionDiagnostic(ctx, connectionDiagnosticID)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connDiag, nil
	}

	connDiag, err := s.cfg.UserClient.AppendDiagnosticTrace(ctx, connectionDiagnosticID, types.NewTraceDiagnosticConnection(
		types.ConnectionDiagnosticTrace_UNKNOWN_ERROR,
		fmt.Sprintf("Unknown error. %s", processStdoutString),
		sshError,
	))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return connDiag, nil
}

func hostKeyCallbackFromCAs(certAuths []types.CertAuthority) (ssh.HostKeyCallback, error) {
	var certPublicKeys []ssh.PublicKey
	for _, ca := range certAuths {
		caCheckers, err := libsshutils.GetCheckers(ca)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		certPublicKeys = append(certPublicKeys, caCheckers...)
	}

	hostKeyCallback, err := sshutils.NewHostKeyCallback(sshutils.HostKeyCallbackConfig{
		GetHostCheckers: func() ([]ssh.PublicKey, error) {
			return certPublicKeys, nil
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return hostKeyCallback, nil
}
