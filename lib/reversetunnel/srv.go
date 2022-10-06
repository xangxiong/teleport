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

package reversetunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/proxy"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// server is a "reverse tunnel server". it exposes the cluster capabilities
// (like access to a cluster's auth) to remote trusted clients
// (also known as 'reverse tunnel agents').
type server struct {
	sync.RWMutex
	Config

	// localAuthClient provides access to the full Auth Server API for the
	// local cluster.
	localAuthClient auth.ClientI
	// localAccessPoint provides access to a cached subset of the Auth
	// Server API.
	localAccessPoint auth.ProxyAccessPoint

	// srv is the "base class" i.e. the underlying SSH server
	srv     *sshutils.Server
	limiter *limiter.Limiter

	// localSite is the  local (our own cluster) tunnel client.
	localSite *localSite

	// cancel function will cancel the
	cancel context.CancelFunc

	// ctx is a context used for signalling and broadcast
	ctx context.Context

	// log specifies the logger
	log log.FieldLogger

	// proxyWatcher monitors changes to the proxies
	// and broadcasts updates
	proxyWatcher *services.ProxyWatcher

	// offlineThreshold is how long to wait for a keep alive message before
	// marking a reverse tunnel connection as invalid.
	offlineThreshold time.Duration
}

// Config is a reverse tunnel server configuration
type Config struct {
	// ID is the ID of this server proxy
	ID string
	// ClusterName is a name of this cluster
	ClusterName string
	// ClientTLS is a TLS config associated with this proxy
	// used to connect to remote auth servers on remote clusters
	ClientTLS *tls.Config
	// Listener is a listener address for reverse tunnel server
	Listener net.Listener
	// HostSigners is a list of host signers
	HostSigners []ssh.Signer
	// HostKeyCallback
	// Limiter is optional request limiter
	Limiter *limiter.Limiter
	// LocalAuthClient provides access to a full AuthClient for the local cluster.
	LocalAuthClient auth.ClientI
	// AccessPoint provides access to a subset of AuthClient of the cluster.
	// AccessPoint caches values and can still return results during connection
	// problems.
	LocalAccessPoint auth.ProxyAccessPoint
	// NewCachingAccessPoint returns new caching access points
	// per remote cluster
	NewCachingAccessPoint auth.NewRemoteProxyCachingAccessPoint
	// Context is a signalling context
	Context context.Context
	// Clock is a clock used in the server, set up to
	// wall clock if not set
	Clock clockwork.Clock

	// KeyGen is a process wide key generator. It is shared to speed up
	// generation of public/private keypairs.
	KeyGen sshca.Authority

	// Ciphers is a list of ciphers that the server supports. If omitted,
	// the defaults will be used.
	Ciphers []string

	// KEXAlgorithms is a list of key exchange (KEX) algorithms that the
	// server supports. If omitted, the defaults will be used.
	KEXAlgorithms []string

	// MACAlgorithms is a list of message authentication codes (MAC) that
	// the server supports. If omitted the defaults will be used.
	MACAlgorithms []string

	// DataDir is a local server data directory
	DataDir string

	// PollingPeriod specifies polling period for internal sync
	// goroutines, used to speed up sync-ups in tests.
	PollingPeriod time.Duration

	// Component is a component used in logs
	Component string

	// Log specifies the logger
	Log log.FieldLogger

	// FIPS means Teleport was started in a FedRAMP/FIPS 140-2 compliant
	// configuration.
	FIPS bool

	// DELETE IN: 8.0.0
	//
	// NewCachingAccessPointOldProxy is an access point that can be configured
	// with the old access point policy until all clusters are migrated to 7.0.0
	// and above.
	NewCachingAccessPointOldProxy auth.NewRemoteProxyCachingAccessPoint

	// PeerClient is a client to peer proxy servers.
	PeerClient *proxy.Client

	// LockWatcher is a lock watcher.
	LockWatcher *services.LockWatcher

	// NodeWatcher is a node watcher.
	NodeWatcher *services.NodeWatcher

	// CertAuthorityWatcher is a cert authority watcher.
	CertAuthorityWatcher *services.CertAuthorityWatcher

	// CircuitBreakerConfig configures the auth client circuit breaker
	CircuitBreakerConfig breaker.Config

	// LocalAuthAddresses is a list of auth servers to use when dialing back to
	// the local cluster.
	LocalAuthAddresses []string
}

// CheckAndSetDefaults checks parameters and sets default values
func (cfg *Config) CheckAndSetDefaults() error {
	if cfg.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	if cfg.ClusterName == "" {
		return trace.BadParameter("missing parameter ClusterName")
	}
	if cfg.ClientTLS == nil {
		return trace.BadParameter("missing parameter ClientTLS")
	}
	if cfg.Listener == nil {
		return trace.BadParameter("missing parameter Listener")
	}
	if cfg.DataDir == "" {
		return trace.BadParameter("missing parameter DataDir")
	}
	if cfg.Context == nil {
		cfg.Context = context.TODO()
	}
	if cfg.PollingPeriod == 0 {
		cfg.PollingPeriod = defaults.HighResPollingPeriod
	}
	if cfg.Limiter == nil {
		var err error
		cfg.Limiter, err = limiter.NewLimiter(limiter.Config{})
		if err != nil {
			return trace.Wrap(err)
		}
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.Component == "" {
		cfg.Component = teleport.Component(teleport.ComponentProxy, teleport.ComponentServer)
	}
	logger := cfg.Log
	if cfg.Log == nil {
		logger = log.StandardLogger()
	}
	cfg.Log = logger.WithFields(log.Fields{
		trace.Component: cfg.Component,
	})
	if cfg.LockWatcher == nil {
		return trace.BadParameter("missing parameter LockWatcher")
	}
	if cfg.NodeWatcher == nil {
		return trace.BadParameter("missing parameter NodeWatcher")
	}
	if cfg.CertAuthorityWatcher == nil {
		return trace.BadParameter("missing parameter CertAuthorityWatcher")
	}
	return nil
}

// NewServer creates and returns a reverse tunnel server which is fully
// initialized but hasn't been started yet
func NewServer(cfg Config) (Server, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	netConfig, err := cfg.LocalAccessPoint.GetClusterNetworkingConfig(cfg.Context)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	offlineThreshold := time.Duration(netConfig.GetKeepAliveCountMax()) * netConfig.GetKeepAliveInterval()

	ctx, cancel := context.WithCancel(cfg.Context)

	proxyWatcher, err := services.NewProxyWatcher(ctx, services.ProxyWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: cfg.Component,
			Client:    cfg.LocalAccessPoint,
			Log:       cfg.Log,
		},
		ProxiesC:    make(chan []types.Server, 10),
		ProxyGetter: cfg.LocalAccessPoint,
	})
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	srv := &server{
		Config:           cfg,
		localAuthClient:  cfg.LocalAuthClient,
		localAccessPoint: cfg.LocalAccessPoint,
		limiter:          cfg.Limiter,
		ctx:              ctx,
		cancel:           cancel,
		proxyWatcher:     proxyWatcher,
		log:              cfg.Log,
		offlineThreshold: offlineThreshold,
	}

	localSite, err := newlocalSite(srv, cfg.ClusterName, cfg.LocalAuthAddresses)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	srv.localSite = localSite

	s, err := sshutils.NewServer(
		teleport.ComponentReverseTunnelServer,
		// TODO(klizhentas): improve interface, use struct instead of parameter list
		// this address is not used
		utils.NetAddr{Addr: "127.0.0.1:1", AddrNetwork: "tcp"},
		srv,
		cfg.HostSigners,
		sshutils.AuthMethods{
			PublicKey: srv.keyAuth,
		},
		sshutils.SetLogger(cfg.Log),
		sshutils.SetLimiter(cfg.Limiter),
		sshutils.SetCiphers(cfg.Ciphers),
		sshutils.SetKEXAlgorithms(cfg.KEXAlgorithms),
		sshutils.SetMACAlgorithms(cfg.MACAlgorithms),
		sshutils.SetFIPS(cfg.FIPS),
	)
	if err != nil {
		return nil, err
	}
	srv.srv = s
	return srv, nil
}

func (s *server) Wait() {
	s.srv.Wait(context.TODO())
}

func (s *server) Start() error {
	go s.srv.Serve(s.Listener)
	return nil
}

func (s *server) Close() error {
	s.cancel()
	s.proxyWatcher.Close()
	return s.srv.Close()
}

// DrainConnections closes the listener and sends reconnects to connected agents without
// closing open connections.
func (s *server) DrainConnections(ctx context.Context) error {
	// Ensure listener is closed before sending reconnects.
	err := s.srv.Close()
	s.srv.Wait(ctx)

	s.RLock()
	s.log.Debugf("Advising reconnect to local site: %s", s.localSite.GetName())
	go s.localSite.adviseReconnect(ctx)

	s.RUnlock()

	return trace.Wrap(err)
}

func (s *server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)

	s.proxyWatcher.Close()
	s.cancel()

	return trace.Wrap(err)
}

func (s *server) HandleNewChan(ctx context.Context, ccx *sshutils.ConnectionContext, nch ssh.NewChannel) {
	// Apply read/write timeouts to the server connection.
	conn := utils.ObeyIdleTimeout(ccx.NetConn,
		s.offlineThreshold,
		"reverse tunnel server")
	sconn := ccx.ServerConn

	channelType := nch.ChannelType()
	switch channelType {
	// Heartbeats can come from nodes or proxies.
	case chanHeartbeat:
		s.handleHeartbeat(conn, sconn, nch)
	// Transport requests come from nodes requesting a connection to the Auth
	// Server through the reverse tunnel.
	case constants.ChanTransport:
		s.handleTransport(sconn, nch)
	default:
		msg := fmt.Sprintf("reversetunnel received unknown channel request %v from %v",
			nch.ChannelType(), sconn)

		// If someone is trying to open a new SSH session by talking to a reverse
		// tunnel, they're most likely using the wrong port number. Give them an
		// explicit hint.
		if channelType == "session" {
			msg = "Cannot open new SSH session on reverse tunnel. Are you connecting to the right port?"
		}
		s.log.Warn(msg)
		s.rejectRequest(nch, ssh.ConnectionFailed, msg)
		return
	}
}

func (s *server) handleTransport(sconn *ssh.ServerConn, nch ssh.NewChannel) {
	s.log.Debugf("Transport request: %v.", nch.ChannelType())
	channel, requestCh, err := nch.Accept()
	if err != nil {
		sconn.Close()
		s.log.Warnf("Failed to accept request: %v.", err)
		return
	}

	t := &transport{
		log:              s.log,
		closeContext:     s.ctx,
		authClient:       s.LocalAccessPoint,
		authServers:      s.LocalAuthAddresses,
		channel:          channel,
		requestCh:        requestCh,
		component:        teleport.ComponentReverseTunnelServer,
		localClusterName: s.ClusterName,
	}
	go t.start()
}

// TODO(awly): unit test this
func (s *server) handleHeartbeat(conn net.Conn, sconn *ssh.ServerConn, nch ssh.NewChannel) {
	s.log.Debugf("New tunnel from %v.", sconn.RemoteAddr())
	if sconn.Permissions.Extensions[utils.ExtIntCertType] != utils.ExtIntCertTypeHost {
		s.log.Error(trace.BadParameter("can't retrieve certificate type in certType"))
		return
	}

	// Extract the role. For proxies, it's another cluster asking to join, for
	// nodes it's a node dialing back.
	val, ok := sconn.Permissions.Extensions[extCertRole]
	if !ok {
		s.log.Errorf("Failed to accept connection, missing %q extension", extCertRole)
		s.rejectRequest(nch, ssh.ConnectionFailed, "unknown role")
		return
	}

	role := types.SystemRole(val)
	switch role {
	// Node is dialing back.
	case types.RoleNode:
		s.handleNewService(role, conn, sconn, nch, types.NodeTunnel)
	default:
		s.log.Errorf("Unsupported role attempting to connect: %v", val)
		s.rejectRequest(nch, ssh.ConnectionFailed, fmt.Sprintf("unsupported role %v", val))
	}
}

func (s *server) handleNewService(role types.SystemRole, conn net.Conn, sconn *ssh.ServerConn, nch ssh.NewChannel, connType types.TunnelType) {
	cluster, rconn, err := s.upsertServiceConn(conn, sconn, connType)
	if err != nil {
		s.log.Errorf("Failed to upsert %s: %v.", role, err)
		sconn.Close()
		return
	}

	ch, req, err := nch.Accept()
	if err != nil {
		s.log.Errorf("Failed to accept on channel: %v.", err)
		sconn.Close()
		return
	}

	go cluster.handleHeartbeat(rconn, ch, req)
}

func (s *server) requireLocalAgentForConn(sconn *ssh.ServerConn, connType types.TunnelType) error {
	// Cluster name was extracted from certificate and packed into extensions.
	clusterName := sconn.Permissions.Extensions[extAuthority]
	if strings.TrimSpace(clusterName) == "" {
		return trace.BadParameter("empty cluster name")
	}

	if s.localSite.domainName == clusterName {
		return nil
	}

	return trace.BadParameter("agent from cluster %s cannot register local service %s", clusterName, connType)
}

func (s *server) getTrustedCAKeysByID(id types.CertAuthID) ([]ssh.PublicKey, error) {
	ca, err := s.localAccessPoint.GetCertAuthority(context.TODO(), id, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sshutils.GetCheckers(ca)
}

func (s *server) keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error) {
	logger := s.log.WithFields(log.Fields{
		"remote": conn.RemoteAddr(),
		"user":   conn.User(),
	})
	// The crypto/x/ssh package won't log the returned error for us, do it
	// manually.
	defer func() {
		if err != nil {
			logger.Warnf("Failed to authenticate client, err: %v.", err)
		}
	}()

	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, trace.BadParameter("server doesn't support provided key type")
	}

	var clusterName, certRole, certType string
	var caType types.CertAuthType
	switch cert.CertType {
	case ssh.HostCert:
		var ok bool
		clusterName, ok = cert.Extensions[utils.CertExtensionAuthority]
		if !ok || clusterName == "" {
			return nil, trace.BadParameter("certificate missing %q extension; this SSH host certificate was not issued by Teleport or issued by an older version of Teleport; try upgrading your Teleport nodes/proxies", utils.CertExtensionAuthority)
		}
		certRole, ok = cert.Extensions[utils.CertExtensionRole]
		if !ok || certRole == "" {
			return nil, trace.BadParameter("certificate missing %q extension; this SSH host certificate was not issued by Teleport or issued by an older version of Teleport; try upgrading your Teleport nodes/proxies", utils.CertExtensionRole)
		}
		certType = utils.ExtIntCertTypeHost
		caType = types.HostCA
	case ssh.UserCert:
		var ok bool
		clusterName, ok = cert.Extensions[teleport.CertExtensionTeleportRouteToCluster]
		if !ok || clusterName == "" {
			clusterName = s.ClusterName
		}
		encRoles, ok := cert.Extensions[teleport.CertExtensionTeleportRoles]
		if !ok || encRoles == "" {
			return nil, trace.BadParameter("certificate missing %q extension; this SSH user certificate was not issued by Teleport or issued by an older version of Teleport; try upgrading your Teleport proxies/auth servers and logging in again (or exporting an identity file, if that's what you used)", teleport.CertExtensionTeleportRoles)
		}
		roles, err := services.UnmarshalCertRoles(encRoles)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if len(roles) == 0 {
			return nil, trace.BadParameter("certificate missing roles in %q extension; make sure your user has some roles assigned (or ask your Teleport admin to) and log in again (or export an identity file, if that's what you used)", teleport.CertExtensionTeleportRoles)
		}
		certRole = roles[0]
		certType = utils.ExtIntCertTypeUser
		caType = types.UserCA
	default:
		return nil, trace.BadParameter("unsupported cert type: %v.", cert.CertType)
	}

	if err := s.checkClientCert(logger, conn.User(), clusterName, cert, caType); err != nil {
		return nil, trace.Wrap(err)
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			extHost:              conn.User(),
			utils.ExtIntCertType: certType,
			extCertRole:          certRole,
			extAuthority:         clusterName,
		},
	}, nil
}

// checkClientCert verifies that client certificate is signed by the recognized
// certificate authority.
func (s *server) checkClientCert(logger *log.Entry, user string, clusterName string, cert *ssh.Certificate, caType types.CertAuthType) error {
	// fetch keys of the certificate authority to check
	// if there is a match
	keys, err := s.getTrustedCAKeysByID(types.CertAuthID{
		Type:       caType,
		DomainName: clusterName,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// match key of the certificate authority with the signature key
	var match bool
	for _, k := range keys {
		if apisshutils.KeysEqual(k, cert.SignatureKey) {
			match = true
			break
		}
	}
	if !match {
		return trace.NotFound("cluster %v has no matching CA keys", clusterName)
	}

	checker := apisshutils.CertChecker{
		FIPS: s.FIPS,
	}
	if err := checker.CheckCert(user, cert); err != nil {
		return trace.BadParameter(err.Error())
	}

	return nil
}

func (s *server) upsertServiceConn(conn net.Conn, sconn *ssh.ServerConn, connType types.TunnelType) (*localSite, *remoteConn, error) {
	s.Lock()
	defer s.Unlock()

	if err := s.requireLocalAgentForConn(sconn, connType); err != nil {
		return nil, nil, trace.Wrap(err)
	}

	nodeID, ok := sconn.Permissions.Extensions[extHost]
	if !ok {
		return nil, nil, trace.BadParameter("host id not found")
	}

	rconn, err := s.localSite.addConn(nodeID, connType, conn, sconn)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return s.localSite, rconn, nil
}

func (s *server) GetSites() ([]RemoteSite, error) {
	s.RLock()
	defer s.RUnlock()
	out := []RemoteSite{s.localSite}

	return out, nil
}

// GetSite returns a RemoteSite. The first attempt is to find and return a
// remote site and that is what is returned if a remote agent has
// connected to this proxy. Next we loop over local sites and try and try and
// return a local site. If that fails, we return a cluster peer. This happens
// when you hit proxy that has never had an agent connect to it. If you end up
// with a cluster peer your best bet is to wait until the agent has discovered
// all proxies behind a load balancer. Note, the cluster peer is a
// services.TunnelConnection that was created by another proxy.
func (s *server) GetSite(name string) (RemoteSite, error) {
	s.RLock()
	defer s.RUnlock()
	if s.localSite.GetName() == name {
		return s.localSite, nil
	}
	return nil, trace.NotFound("cluster %q is not found", name)
}

// GetProxyPeerClient returns the proxy peer client
func (s *server) GetProxyPeerClient() *proxy.Client {
	return s.PeerClient
}

// alwaysClose forces onSiteTunnelClose to remove and close
// the site by always returning false from HasValidConnections.
type alwaysClose struct {
	RemoteSite
}

func (a *alwaysClose) HasValidConnections() bool {
	return false
}

// siteCloser is used by onSiteTunnelClose to determine if a site should be closed
// when a tunnel is closed
type siteCloser interface {
	GetName() string
	HasValidConnections() bool
	io.Closer
}

// onSiteTunnelClose will close and stop tracking the site with the given name
// if it has 0 active tunnels. This is done here to ensure that no new tunnels
// can be established while cleaning up a site.
func (s *server) onSiteTunnelClose(site siteCloser) error {
	s.Lock()
	defer s.Unlock()

	if site.HasValidConnections() {
		return nil
	}

	return trace.NotFound("site %q is not found", site.GetName())
}

func (s *server) rejectRequest(ch ssh.NewChannel, reason ssh.RejectionReason, msg string) {
	if err := ch.Reject(reason, msg); err != nil {
		s.log.Warnf("Failed rejecting new channel request: %v", err)
	}
}

// createRemoteAccessPoint creates a new access point for the remote cluster.
// Checks if the cluster that is connecting is a pre-v8 cluster. If it is,
// don't assume the newer organization of cluster configuration resources
// (RFD 28) because older proxy servers will reject that causing the cache
// to go into a re-sync loop.
func createRemoteAccessPoint(srv *server, clt auth.ClientI, version, domainName string) (auth.RemoteProxyAccessPoint, error) {
	ok, err := utils.MinVerWithoutPreRelease(version, utils.VersionBeforeAlpha("8.0.0"))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	accessPointFunc := srv.Config.NewCachingAccessPoint
	if !ok {
		srv.log.Debugf("cluster %q running %q is connecting, loading old cache policy.", domainName, version)
		accessPointFunc = srv.Config.NewCachingAccessPointOldProxy
	}

	// Configure access to the cached subset of the Auth Server API of the remote
	// cluster this remote site provides access to.
	accessPoint, err := accessPointFunc(clt, []string{"reverse", domainName})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return accessPoint, nil
}

// getRemoteAuthVersion sends a version request to the remote agent.
func getRemoteAuthVersion(ctx context.Context, sconn ssh.Conn) (string, error) {
	errorCh := make(chan error, 1)
	versionCh := make(chan string, 1)

	go func() {
		ok, payload, err := sconn.SendRequest(versionRequest, true, nil)
		if err != nil {
			errorCh <- err
			return
		}
		if !ok {
			errorCh <- trace.BadParameter("no response to %v request", versionRequest)
			return
		}

		versionCh <- string(payload)
	}()

	select {
	case ver := <-versionCh:
		return ver, nil
	case err := <-errorCh:
		return "", trace.Wrap(err)
	case <-time.After(defaults.WaitCopyTimeout):
		return "", trace.BadParameter("timeout waiting for version")
	case <-ctx.Done():
		return "", trace.Wrap(ctx.Err())
	}
}

const (
	extHost      = "host@teleport"
	extAuthority = "auth@teleport"
	extCertRole  = "role"

	versionRequest = "x-teleport-version"
)
