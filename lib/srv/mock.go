/*
Copyright 2015-2020 Gravitational, Inc.

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

package srv

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/user"
	"testing"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/keystore"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/events/eventstest"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/pam"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
)

func NewTestServerContext(t *testing.T, srv Server, roleSet services.RoleSet) *ServerContext {
	usr, err := user.Current()
	require.NoError(t, err)

	cert, err := apisshutils.ParseCertificate([]byte(fixtures.UserCertificateStandard))
	require.NoError(t, err)

	sshConn := &mockSSHConn{}
	sshConn.localAddr, _ = utils.ParseAddr("127.0.0.1:3022")
	sshConn.remoteAddr, _ = utils.ParseAddr("10.0.0.5:4817")

	ctx, cancel := context.WithCancel(context.Background())
	clusterName := "localhost"
	scx := &ServerContext{
		Entry: logrus.NewEntry(logrus.StandardLogger()),
		ConnectionContext: &sshutils.ConnectionContext{
			ServerConn: &ssh.ServerConn{Conn: sshConn},
		},
		env:                    make(map[string]string),
		SessionRecordingConfig: types.DefaultSessionRecordingConfig(),
		IsTestStub:             true,
		ClusterName:            clusterName,
		srv:                    srv,
		Identity: IdentityContext{
			Login:        usr.Username,
			TeleportUser: "teleportUser",
			Certificate:  cert,
			// roles do not actually exist in mock backend, just need a non-nil
			// access checker to avoid panic
			AccessChecker: services.NewAccessCheckerWithRoleSet(
				&services.AccessInfo{Roles: roleSet.RoleNames()}, clusterName, roleSet),
		},
		cancelContext: ctx,
		cancel:        cancel,
	}

	scx.ExecRequest = &localExec{Ctx: scx}

	scx.cmdr, scx.cmdw, err = os.Pipe()
	require.NoError(t, err)

	scx.contr, scx.contw, err = os.Pipe()
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, scx.Close()) })

	return scx
}

func NewMockServer(t *testing.T) *MockServer {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:  t.TempDir(),
		Clock: clock,
	})
	require.NoError(t, err)

	clusterName, err := services.NewClusterNameWithRandomID(types.ClusterNameSpecV2{
		ClusterName: "localhost",
	})
	require.NoError(t, err)

	staticTokens, err := types.NewStaticTokens(types.StaticTokensSpecV2{
		StaticTokens: []types.ProvisionTokenV1{},
	})
	require.NoError(t, err)

	authCfg := &auth.InitConfig{
		Backend:      bk,
		Authority:    testauthority.New(),
		ClusterName:  clusterName,
		StaticTokens: staticTokens,
		KeyStoreConfig: keystore.Config{
			RSAKeyPairSource: testauthority.New().GenerateKeyPair,
		},
	}

	authServer, err := auth.NewServer(authCfg, auth.WithClock(clock))
	require.NoError(t, err)

	return &MockServer{
		auth:        authServer,
		MockEmitter: &eventstest.MockEmitter{},
		clock:       clock,
	}
}

type MockServer struct {
	*eventstest.MockEmitter
	auth      *auth.Server
	component string
	clock     clockwork.FakeClock
}

// ID is the unique ID of the server.
func (m *MockServer) ID() string {
	return "testID"
}

// HostUUID is the UUID of the underlying host. For the forwarding
// server this is the proxy the forwarding server is running in.
func (m *MockServer) HostUUID() string {
	return "testHostUUID"
}

// GetNamespace returns the namespace the server was created in.
func (m *MockServer) GetNamespace() string {
	return "testNamespace"
}

// AdvertiseAddr is the publicly addressable address of this server.
func (m *MockServer) AdvertiseAddr() string {
	return "testAdvertiseAddr"
}

// Component is the type of server, forwarding or regular.
func (m *MockServer) Component() string {
	return m.component
}

// PermitUserEnvironment returns if reading environment variables upon
// startup is allowed.
func (m *MockServer) PermitUserEnvironment() bool {
	return false
}

// GetAccessPoint returns an AccessPoint for this cluster.
func (m *MockServer) GetAccessPoint() AccessPoint {
	return m.auth
}

// GetDataDir returns data directory of the server
func (m *MockServer) GetDataDir() string {
	return "testDataDir"
}

// GetPAM returns PAM configuration for this server.
func (m *MockServer) GetPAM() (*pam.Config, error) {
	return &pam.Config{}, nil
}

// GetClock returns a clock setup for the server
func (m *MockServer) GetClock() clockwork.Clock {
	if m.clock != nil {
		return m.clock
	}
	return clockwork.NewRealClock()
}

// GetInfo returns a services.Server that represents this server.
func (m *MockServer) GetInfo() types.Server {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	return &types.ServerV2{
		Kind:    types.KindNode,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      "",
			Namespace: "",
			Labels:    make(map[string]string),
		},
		Spec: types.ServerSpecV2{
			CmdLabels: make(map[string]types.CommandLabelV2),
			Addr:      "",
			Hostname:  hostname,
			UseTunnel: false,
			Version:   teleport.Version,
		},
	}
}

func (m *MockServer) TargetMetadata() apievents.ServerMetadata {
	return apievents.ServerMetadata{}
}

// UseTunnel used to determine if this node has connected to this cluster
// using reverse tunnel.
func (m *MockServer) UseTunnel() bool {
	return false
}

// OpenBPFSession is a nop since the session must be run on the actual node
func (m *MockServer) OpenBPFSession(ctx *ServerContext) (uint64, error) {
	return 0, nil
}

// CloseBPFSession is anop since the session must be run on the actual node
func (m *MockServer) CloseBPFSession(ctx *ServerContext) error {
	return nil
}

// OpenRestrictedSession is a nop since the session must be run on the actual node
func (m *MockServer) OpenRestrictedSession(ctx *ServerContext, cgroupID uint64) {}

// CloseRestrictedSession is a nop since the session must be run on the actual node
func (m *MockServer) CloseRestrictedSession(ctx *ServerContext, cgroupID uint64) {}

// Context returns server shutdown context
func (m *MockServer) Context() context.Context {
	return context.Background()
}

// GetUtmpPath returns the path of the user accounting database and log. Returns empty for system defaults.
func (m *MockServer) GetUtmpPath() (utmp, wtmp string) {
	return "test", "test"
}

// GetLockWatcher gets the server's lock watcher.
func (m *MockServer) GetLockWatcher() *services.LockWatcher {
	return nil
}

// GetCreateHostUser gets whether the server allows host user creation
// or not
func (m *MockServer) GetCreateHostUser() bool {
	return false
}

// GetHostUsers
func (m *MockServer) GetHostUsers() HostUsers {
	return nil
}

// Implementation of ssh.Conn interface.
type mockSSHConn struct {
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *mockSSHConn) User() string {
	return ""
}

func (c *mockSSHConn) SessionID() []byte {
	return []byte{1, 2, 3}
}

func (c *mockSSHConn) ClientVersion() []byte {
	return []byte{1}
}

func (c *mockSSHConn) ServerVersion() []byte {
	return []byte{1}
}

func (c *mockSSHConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *mockSSHConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *mockSSHConn) Close() error {
	return nil
}

func (c *mockSSHConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return false, nil, nil
}

func (c *mockSSHConn) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, nil
}

func (c *mockSSHConn) Wait() error {
	return nil
}

type mockSSHChannel struct {
	stdIn  io.ReadCloser
	stdOut io.WriteCloser
	stdErr io.ReadWriter
}

func newMockSSHChannel() ssh.Channel {
	stdIn, stdOut := io.Pipe()
	return &mockSSHChannel{
		stdIn:  stdIn,
		stdOut: stdOut,
		stdErr: new(bytes.Buffer),
	}
}

// Read reads up to len(data) bytes from the channel.
func (c *mockSSHChannel) Read(data []byte) (int, error) {
	return c.stdIn.Read(data)
}

// Write writes len(data) bytes to the channel.
func (c *mockSSHChannel) Write(data []byte) (int, error) {
	return c.stdOut.Write(data)
}

// Close signals end of channel use. No data may be sent after this
// call.
func (c *mockSSHChannel) Close() error {
	return trace.NewAggregate(c.stdIn.Close(), c.stdOut.Close())
}

// CloseWrite signals the end of sending in-band
// data. Requests may still be sent, and the other side may
// still send data
func (c *mockSSHChannel) CloseWrite() error {
	return trace.NewAggregate(c.stdOut.Close())
}

// SendRequest sends a channel request.  If wantReply is true,
// it will wait for a reply and return the result as a
// boolean, otherwise the return value will be false. Channel
// requests are out-of-band messages so they may be sent even
// if the data stream is closed or blocked by flow control.
// If the channel is closed before a reply is returned, io.EOF
// is returned.
func (c *mockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

// Stderr returns an io.ReadWriter that writes to this channel
// with the extended data type set to stderr. Stderr may
// safely be read and written from a different goroutine than
// Read and Write respectively.
func (c *mockSSHChannel) Stderr() io.ReadWriter {
	return c.stdErr
}
