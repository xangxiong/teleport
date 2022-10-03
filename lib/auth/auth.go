/*
Copyright 2015-2019 Gravitational, Inc.

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

// Package auth implements certificate signing authority and access control server
// Authority server is composed of several parts:
//
// * Authority server itself that implements signing and acl logic
// * HTTP server wrapper for authority server
// * HTTP client wrapper
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	insecurerand "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth/keystore"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/inventory"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/interval"
)

const (
	ErrFieldKeyUserMaxedAttempts = "maxed-attempts"

	// MaxFailedAttemptsErrMsg is a user friendly error message that tells a user that they are locked.
	MaxFailedAttemptsErrMsg = "too many incorrect attempts, please try again later"
)

// ServerOption allows setting options as functional arguments to Server
type ServerOption func(*Server) error

// NewServer creates and configures a new Server instance
func NewServer(cfg *InitConfig, opts ...ServerOption) (*Server, error) {
	var err error

	if cfg.Trust == nil {
		cfg.Trust = local.NewCAService(cfg.Backend)
	}
	if cfg.Presence == nil {
		cfg.Presence = local.NewPresenceService(cfg.Backend)
	}
	if cfg.Provisioner == nil {
		cfg.Provisioner = local.NewProvisioningService(cfg.Backend)
	}
	if cfg.Access == nil {
		cfg.Access = local.NewAccessService(cfg.Backend)
	}
	if cfg.DynamicAccessExt == nil {
		cfg.DynamicAccessExt = local.NewDynamicAccessService(cfg.Backend)
	}
	if cfg.ClusterConfiguration == nil {
		clusterConfig, err := local.NewClusterConfigurationService(cfg.Backend)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		cfg.ClusterConfiguration = clusterConfig
	}
	if cfg.Restrictions == nil {
		cfg.Restrictions = local.NewRestrictionsService(cfg.Backend)
	}
	if cfg.Status == nil {
		cfg.Status = local.NewStatusService(cfg.Backend)
	}
	if cfg.Events == nil {
		cfg.Events = local.NewEventsService(cfg.Backend)
	}
	if cfg.AuditLog == nil {
		cfg.AuditLog = events.NewDiscardAuditLog()
	}
	if cfg.Emitter == nil {
		cfg.Emitter = events.NewDiscardEmitter()
	}
	if cfg.Streamer == nil {
		cfg.Streamer = events.NewDiscardEmitter()
	}
	if cfg.SessionTrackerService == nil {
		cfg.SessionTrackerService, err = local.NewSessionTrackerService(cfg.Backend)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if cfg.AssertionReplayService == nil {
		cfg.AssertionReplayService = local.NewAssertionReplayService(cfg.Backend)
	}
	if cfg.KeyStoreConfig.RSAKeyPairSource == nil {
		native.PrecomputeKeys()
		cfg.KeyStoreConfig.RSAKeyPairSource = native.GenerateKeyPair
	}
	if cfg.KeyStoreConfig.HostUUID == "" {
		cfg.KeyStoreConfig.HostUUID = cfg.HostUUID
	}

	limiter, err := limiter.NewConnectionsLimiter(limiter.Config{
		MaxConnections: defaults.LimiterMaxConcurrentSignatures,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	keyStore, err := keystore.NewKeyStore(cfg.KeyStoreConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	services := &Services{
		Trust:                 cfg.Trust,
		Presence:              cfg.Presence,
		Provisioner:           cfg.Provisioner,
		Access:                cfg.Access,
		DynamicAccessExt:      cfg.DynamicAccessExt,
		ClusterConfiguration:  cfg.ClusterConfiguration,
		Restrictions:          cfg.Restrictions,
		IAuditLog:             cfg.AuditLog,
		Events:                cfg.Events,
		SessionTrackerService: cfg.SessionTrackerService,
		StatusInternal:        cfg.Status,
	}

	closeCtx, cancelFunc := context.WithCancel(context.TODO())
	as := Server{
		bk:              cfg.Backend,
		limiter:         limiter,
		Authority:       cfg.Authority,
		AuthServiceName: cfg.AuthServiceName,
		ServerID:        cfg.HostUUID,
		cancelFunc:      cancelFunc,
		closeCtx:        closeCtx,
		emitter:         cfg.Emitter,
		streamer:        cfg.Streamer,
		unstable:        local.NewUnstableService(cfg.Backend, cfg.AssertionReplayService),
		Services:        services,
		Cache:           services,
		keyStore:        keyStore,
		inventory:       inventory.NewController(cfg.Presence),
	}
	for _, o := range opts {
		if err := o(&as); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if as.clock == nil {
		as.clock = clockwork.NewRealClock()
	}

	return &as, nil
}

type Services struct {
	services.Trust
	services.Presence
	services.Provisioner
	// services.Identity
	services.Access
	services.DynamicAccessExt
	services.ClusterConfiguration
	services.Restrictions
	services.SessionTrackerService
	services.ConnectionsDiagnostic
	services.StatusInternal
	types.Events
	events.IAuditLog
}

// Server keeps the cluster together. It acts as a certificate authority (CA) for
// a cluster and:
//   - generates the keypair for the node it's running on
//   - invites other SSH nodes to a cluster, by issuing invite tokens
//   - adds other SSH nodes to a cluster, by checking their token and signing their keys
//   - same for users and their sessions
//   - checks public keys to see if they're signed by it (can be trusted or not)
type Server struct {
	lock  sync.RWMutex
	clock clockwork.Clock
	bk    backend.Backend

	closeCtx   context.Context
	cancelFunc context.CancelFunc

	sshca.Authority

	// AuthServiceName is a human-readable name of this CA. If several Auth services are running
	// (managing multiple teleport clusters) this field is used to tell them apart in UIs
	// It usually defaults to the hostname of the machine the Auth service runs on.
	AuthServiceName string

	// ServerID is the server ID of this auth server.
	ServerID string

	// unstable implements unstable backend methods not suitable
	// for inclusion in Services.
	unstable local.UnstableService

	// Services encapsulate services - provisioner, trust, etc. used by the auth
	// server in a separate structure. Reads through Services hit the backend.
	*Services

	// Cache should either be the same as Services, or a caching layer over it.
	// As it's an interface (and thus directly implementing all of its methods)
	// its embedding takes priority over Services (which only indirectly
	// implements its methods), thus any implemented GetFoo method on both Cache
	// and Services will call the one from Cache. To bypass the cache, call the
	// method on Services instead.
	Cache

	// privateKey is used in tests to use pre-generated private keys
	privateKey []byte

	// cipherSuites is a list of ciphersuites that the auth server supports.
	cipherSuites []uint16

	// limiter limits the number of active connections per client IP.
	limiter *limiter.ConnectionsLimiter

	// Emitter is events emitter, used to submit discrete events
	emitter apievents.Emitter

	// streamer is events sessionstreamer, used to create continuous
	// session related streams
	streamer events.Streamer

	// keyStore is an interface for interacting with private keys in CAs which
	// may be backed by HSMs
	keyStore keystore.KeyStore

	// lockWatcher is a lock watcher, used to verify cert generation requests.
	lockWatcher *services.LockWatcher

	inventory *inventory.Controller
}

func (a *Server) CloseContext() context.Context {
	return a.closeCtx
}

// SetLockWatcher sets the lock watcher.
func (a *Server) SetLockWatcher(lockWatcher *services.LockWatcher) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.lockWatcher = lockWatcher
}

func (a *Server) checkLockInForce(mode constants.LockingMode, targets []types.LockTarget) error {
	a.lock.RLock()
	defer a.lock.RUnlock()
	if a.lockWatcher == nil {
		return trace.BadParameter("lockWatcher is not set")
	}
	return a.lockWatcher.CheckLockInForce(mode, targets...)
}

// runPeriodicOperations runs some periodic bookkeeping operations
// performed by auth server
func (a *Server) runPeriodicOperations() {
	ctx := context.TODO()
	// run periodic functions with a semi-random period
	// to avoid contention on the database in case if there are multiple
	// auth servers running - so they don't compete trying
	// to update the same resources.
	r := insecurerand.New(insecurerand.NewSource(a.GetClock().Now().UnixNano()))
	period := defaults.HighResPollingPeriod + time.Duration(r.Intn(int(defaults.HighResPollingPeriod/time.Second)))*time.Second
	log.Debugf("Ticking with period: %v.", period)
	a.lock.RLock()
	ticker := a.clock.NewTicker(period)
	a.lock.RUnlock()
	// Create a ticker with jitter
	heartbeatCheckTicker := interval.New(interval.Config{
		Duration: apidefaults.ServerKeepAliveTTL() * 2,
		Jitter:   utils.NewSeventhJitter(),
	})
	missedKeepAliveCount := 0
	defer ticker.Stop()
	defer heartbeatCheckTicker.Stop()

	for {
		select {
		case <-a.closeCtx.Done():
			return
		case <-ticker.Chan():
			err := a.autoRotateCertAuthorities(ctx)
			if err != nil {
				if trace.IsCompareFailed(err) {
					log.Debugf("Cert authority has been updated concurrently: %v.", err)
				} else {
					log.Errorf("Failed to perform cert rotation check: %v.", err)
				}
			}
		case <-heartbeatCheckTicker.Next():
			nodes, err := a.GetNodes(ctx, apidefaults.Namespace)
			if err != nil {
				log.Errorf("Failed to load nodes for heartbeat metric calculation: %v", err)
			}
			for _, node := range nodes {
				if services.NodeHasMissedKeepAlives(node) {
					missedKeepAliveCount++
				}
			}
		}
	}
}

func (a *Server) Close() error {
	a.cancelFunc()

	var errs []error

	if err := a.inventory.Close(); err != nil {
		errs = append(errs, err)
	}

	if a.bk != nil {
		if err := a.bk.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return trace.NewAggregate(errs...)
}

func (a *Server) GetClock() clockwork.Clock {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.clock
}

// SetClock sets clock, used in tests
func (a *Server) SetClock(clock clockwork.Clock) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.clock = clock
}

// SetAuditLog sets the server's audit log
func (a *Server) SetAuditLog(auditLog events.IAuditLog) {
	a.Services.IAuditLog = auditLog
}

// GetDomainName returns the domain name that identifies this authority server.
// Also known as "cluster name"
func (a *Server) GetDomainName() (string, error) {
	clusterName, err := a.GetClusterName()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return clusterName.GetClusterName(), nil
}

// GetClusterCACert returns the PEM-encoded TLS certs for the local cluster. If
// the cluster has multiple TLS certs, they will all be concatenated.
func (a *Server) GetClusterCACert(ctx context.Context) (*proto.GetClusterCACertResponse, error) {
	clusterName, err := a.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Extract the TLS CA for this cluster.
	hostCA, err := a.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.HostCA,
		DomainName: clusterName.GetClusterName(),
	}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs := services.GetTLSCerts(hostCA)
	if len(certs) < 1 {
		return nil, trace.NotFound("no tls certs found in host CA")
	}
	allCerts := bytes.Join(certs, []byte("\n"))

	return &proto.GetClusterCACertResponse{
		TLSCA: allCerts,
	}, nil
}

// GenerateHostCert uses the private key of the CA to sign the public key of the host
// (along with meta data like host ID, node name, roles, and ttl) to generate a host certificate.
func (a *Server) GenerateHostCert(hostPublicKey []byte, hostID, nodeName string, principals []string, clusterName string, role types.SystemRole, ttl time.Duration) ([]byte, error) {
	domainName, err := a.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// get the certificate authority that will be signing the public key of the host
	ca, err := a.Services.GetCertAuthority(context.TODO(), types.CertAuthID{
		Type:       types.HostCA,
		DomainName: domainName,
	}, true)
	if err != nil {
		return nil, trace.BadParameter("failed to load host CA for %q: %v", domainName, err)
	}

	caSigner, err := a.keyStore.GetSSHSigner(ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// create and sign!
	return a.generateHostCert(services.HostCertParams{
		CASigner:      caSigner,
		PublicHostKey: hostPublicKey,
		HostID:        hostID,
		NodeName:      nodeName,
		Principals:    principals,
		ClusterName:   clusterName,
		Role:          role,
		TTL:           ttl,
	})
}

func (a *Server) generateHostCert(p services.HostCertParams) ([]byte, error) {
	authPref, err := a.GetAuthPreference(context.TODO())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if p.Role == types.RoleNode {
		if lockErr := a.checkLockInForce(authPref.GetLockingMode(),
			[]types.LockTarget{{Node: p.HostID}, {Node: HostFQDN(p.HostID, p.ClusterName)}},
		); lockErr != nil {
			return nil, trace.Wrap(lockErr)
		}
	}
	return a.Authority.GenerateHostCert(p)
}

// GetKeyStore returns the KeyStore used by the auth server
func (a *Server) GetKeyStore() keystore.KeyStore {
	return a.keyStore
}

// ExtractHostID returns host id based on the hostname
func ExtractHostID(hostName string, clusterName string) (string, error) {
	suffix := "." + clusterName
	if !strings.HasSuffix(hostName, suffix) {
		return "", trace.BadParameter("expected suffix %q in %q", suffix, hostName)
	}
	return strings.TrimSuffix(hostName, suffix), nil
}

// HostFQDN consists of host UUID and cluster name joined via .
func HostFQDN(hostUUID, clusterName string) string {
	return fmt.Sprintf("%v.%v", hostUUID, clusterName)
}

// GenerateHostCerts generates new host certificates (signed
// by the host certificate authority) for a node.
func (a *Server) GenerateHostCerts(ctx context.Context, req *proto.HostCertsRequest) (*proto.Certs, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := req.Role.Check(); err != nil {
		return nil, err
	}

	if err := a.limiter.AcquireConnection(req.Role.String()); err != nil {
		log.Debugf("Node %q [%v] is rate limited: %v.", req.NodeName, req.HostID, req.Role)
		return nil, trace.Wrap(err)
	}
	defer a.limiter.ReleaseConnection(req.Role.String())

	clusterName, err := a.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// If the request contains 0.0.0.0, this implies an advertise IP was not
	// specified on the node. Try and guess what the address by replacing 0.0.0.0
	// with the RemoteAddr as known to the Auth Server.
	if apiutils.SliceContainsStr(req.AdditionalPrincipals, defaults.AnyAddress) {
		remoteHost, err := utils.Host(req.RemoteAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req.AdditionalPrincipals = utils.ReplaceInSlice(
			req.AdditionalPrincipals,
			defaults.AnyAddress,
			remoteHost)
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey(req.PublicSSHKey); err != nil {
		return nil, trace.BadParameter("failed to parse SSH public key")
	}
	cryptoPubKey, err := tlsca.ParsePublicKeyPEM(req.PublicTLSKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// get the certificate authority that will be signing the public key of the host,
	client := a.Cache
	if req.NoCache {
		client = a.Services
	}
	ca, err := client.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.HostCA,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return nil, trace.BadParameter("failed to load host CA for %q: %v", clusterName.GetClusterName(), err)
	}

	// could be a couple of scenarios, either client data is out of sync,
	// or auth server is out of sync, either way, for now check that
	// cache is out of sync, this will result in higher read rate
	// to the backend, which is a fine tradeoff
	if !req.NoCache && req.Rotation != nil && !req.Rotation.Matches(ca.GetRotation()) {
		log.Debugf("Client sent rotation state %v, cache state is %v, using state from the DB.", req.Rotation, ca.GetRotation())
		ca, err = a.Services.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, true)
		if err != nil {
			return nil, trace.BadParameter("failed to load host CA for %q: %v", clusterName.GetClusterName(), err)
		}
		if !req.Rotation.Matches(ca.GetRotation()) {
			return nil, trace.BadParameter(""+
				"the client expected state is out of sync, server rotation state: %v, "+
				"client rotation state: %v, re-register the client from scratch to fix the issue.",
				ca.GetRotation(), req.Rotation)
		}
	}

	isAdminRole := req.Role == types.RoleAdmin

	cert, signer, err := a.keyStore.GetTLSCertAndSigner(ca)
	if trace.IsNotFound(err) && isAdminRole {
		// If there is no local TLS signer found in the host CA ActiveKeys, this
		// auth server may have a newly configured HSM and has only populated
		// local keys in the AdditionalTrustedKeys until the next CA rotation.
		// This is the only case where we should be able to get a signer from
		// AdditionalTrustedKeys but not ActiveKeys.
		cert, signer, err = a.keyStore.GetAdditionalTrustedTLSCertAndSigner(ca)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsAuthority, err := tlsca.FromCertAndSigner(cert, signer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	caSigner, err := a.keyStore.GetSSHSigner(ca)
	if trace.IsNotFound(err) && isAdminRole {
		// If there is no local SSH signer found in the host CA ActiveKeys, this
		// auth server may have a newly configured HSM and has only populated
		// local keys in the AdditionalTrustedKeys until the next CA rotation.
		// This is the only case where we should be able to get a signer from
		// AdditionalTrustedKeys but not ActiveKeys.
		caSigner, err = a.keyStore.GetAdditionalTrustedSSHSigner(ca)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// generate host SSH certificate
	hostSSHCert, err := a.generateHostCert(services.HostCertParams{
		CASigner:      caSigner,
		PublicHostKey: req.PublicSSHKey,
		HostID:        req.HostID,
		NodeName:      req.NodeName,
		ClusterName:   clusterName.GetClusterName(),
		Role:          req.Role,
		Principals:    req.AdditionalPrincipals,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.Role == types.RoleInstance && len(req.SystemRoles) == 0 {
		return nil, trace.BadParameter("cannot generate instance cert with no system roles")
	}

	systemRoles := make([]string, 0, len(req.SystemRoles))
	for _, r := range req.SystemRoles {
		systemRoles = append(systemRoles, string(r))
	}

	// generate host TLS certificate
	identity := tlsca.Identity{
		Username:        HostFQDN(req.HostID, clusterName.GetClusterName()),
		Groups:          []string{req.Role.String()},
		TeleportCluster: clusterName.GetClusterName(),
		SystemRoles:     systemRoles,
	}
	subject, err := identity.Subject()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certRequest := tlsca.CertificateRequest{
		Clock:     a.clock,
		PublicKey: cryptoPubKey,
		Subject:   subject,
		NotAfter:  a.clock.Now().UTC().Add(defaults.CATTL),
		DNSNames:  append([]string{}, req.AdditionalPrincipals...),
	}

	// API requests need to specify a DNS name, which must be present in the certificate's DNS Names.
	// The target DNS is not always known in advance, so we add a default one to all certificates.
	certRequest.DNSNames = append(certRequest.DNSNames, DefaultDNSNamesForRole(req.Role)...)
	// Unlike additional principals, DNS Names is x509 specific and is limited
	// to services with TLS endpoints (e.g. auth, proxies)
	if (types.SystemRoles{req.Role}).IncludeAny(types.RoleAuth, types.RoleAdmin, types.RoleProxy) {
		certRequest.DNSNames = append(certRequest.DNSNames, req.DNSNames...)
	}
	hostTLSCert, err := tlsAuthority.GenerateCertificate(certRequest)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &proto.Certs{
		SSH:        hostSSHCert,
		TLS:        hostTLSCert,
		TLSCACerts: services.GetTLSCerts(ca),
		SSHCACerts: services.GetSSHCheckingKeys(ca),
	}, nil
}

// UnstableAssertSystemRole is not a stable part of the public API. Used by older
// instances to prove that they hold a given system role.
// DELETE IN: 12.0 (deprecated in v11, but required for back-compat with v10 clients)
func (a *Server) UnstableAssertSystemRole(ctx context.Context, req proto.UnstableSystemRoleAssertion) error {
	return trace.Wrap(a.unstable.AssertSystemRole(ctx, req))
}

func (a *Server) UnstableGetSystemRoleAssertions(ctx context.Context, serverID string, assertionID string) (proto.UnstableSystemRoleAssertionSet, error) {
	set, err := a.unstable.GetSystemRoleAssertions(ctx, serverID, assertionID)
	return set, trace.Wrap(err)
}

func (a *Server) RegisterInventoryControlStream(ics client.UpstreamInventoryControlStream, hello proto.UpstreamInventoryHello) error {
	// upstream hello is pulled and checked at rbac layer. we wait to send the downstream hello until we get here
	// in order to simplify creation of in-memory streams when dealing with local auth (note: in theory we could
	// send hellos simultaneously to slightly improve perf, but there is a potential benefit to having the
	// downstream hello serve double-duty as an indicator of having successfully transitioned the rbac layer).
	downstreamHello := proto.DownstreamInventoryHello{
		Version:  teleport.Version,
		ServerID: a.ServerID,
	}
	if err := ics.Send(a.CloseContext(), downstreamHello); err != nil {
		return trace.Wrap(err)
	}
	a.inventory.RegisterControlStream(ics, hello)
	return nil
}

// MakeLocalInventoryControlStream sets up an in-memory control stream which automatically registers with this auth
// server upon hello exchange.
func (a *Server) MakeLocalInventoryControlStream(opts ...client.ICSPipeOption) client.DownstreamInventoryControlStream {
	upstream, downstream := client.InventoryControlStreamPipe(opts...)
	go func() {
		select {
		case msg := <-upstream.Recv():
			hello, ok := msg.(proto.UpstreamInventoryHello)
			if !ok {
				upstream.CloseWithError(trace.BadParameter("expected upstream hello, got: %T", msg))
				return
			}
			if err := a.RegisterInventoryControlStream(upstream, hello); err != nil {
				upstream.CloseWithError(err)
				return
			}
		case <-upstream.Done():
		case <-a.CloseContext().Done():
			upstream.Close()
		}
	}()
	return downstream
}

func (a *Server) GetInventoryStatus(ctx context.Context, req proto.InventoryStatusRequest) proto.InventoryStatusSummary {
	var rsp proto.InventoryStatusSummary
	if req.Connected {
		a.inventory.Iter(func(handle inventory.UpstreamHandle) {
			rsp.Connected = append(rsp.Connected, handle.Hello())
		})
	}
	return rsp
}

func (a *Server) PingInventory(ctx context.Context, req proto.InventoryPingRequest) (proto.InventoryPingResponse, error) {
	stream, ok := a.inventory.GetControlStream(req.ServerID)
	if !ok {
		return proto.InventoryPingResponse{}, trace.NotFound("no control stream found for server %q", req.ServerID)
	}

	d, err := stream.Ping(ctx)
	if err != nil {
		return proto.InventoryPingResponse{}, trace.Wrap(err)
	}

	return proto.InventoryPingResponse{
		Duration: d,
	}, nil
}

// TokenExpiredOrNotFound is a special message returned by the auth server when provisioning
// tokens are either past their TTL, or could not be found.
const TokenExpiredOrNotFound = "token expired or not found"

// ValidateToken takes a provisioning token value and finds if it's valid. Returns
// a list of roles this token allows its owner to assume and token labels, or an error if the token
// cannot be found.
func (a *Server) ValidateToken(ctx context.Context, token string) (types.ProvisionToken, error) {
	tkns, err := a.GetStaticTokens()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// First check if the token is a static token. If it is, return right away.
	// Static tokens have no expiration.
	for _, st := range tkns.GetStaticTokens() {
		if subtle.ConstantTimeCompare([]byte(st.GetName()), []byte(token)) == 1 {
			return st, nil
		}
	}

	// If it's not a static token, check if it's a ephemeral token in the backend.
	// If a ephemeral token is found, make sure it's still valid.
	tok, err := a.GetToken(ctx, token)
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.AccessDenied(TokenExpiredOrNotFound)
		}
		return nil, trace.Wrap(err)
	}
	if !a.checkTokenTTL(tok) {
		return nil, trace.AccessDenied(TokenExpiredOrNotFound)
	}

	return tok, nil
}

// checkTokenTTL checks if the token is still valid. If it is not, the token
// is removed from the backend and returns false. Otherwise returns true.
func (a *Server) checkTokenTTL(tok types.ProvisionToken) bool {
	ctx := context.TODO()
	now := a.clock.Now().UTC()
	if tok.Expiry().Before(now) {
		err := a.DeleteToken(ctx, tok.GetName())
		if err != nil {
			if !trace.IsNotFound(err) {
				log.Warnf("Unable to delete token from backend: %v.", err)
			}
		}
		return false
	}
	return true
}

func (a *Server) DeleteNamespace(namespace string) error {
	ctx := context.TODO()
	if namespace == apidefaults.Namespace {
		return trace.AccessDenied("can't delete default namespace")
	}
	nodes, err := a.GetNodes(ctx, namespace)
	if err != nil {
		return trace.Wrap(err)
	}
	if len(nodes) != 0 {
		return trace.BadParameter("can't delete namespace %v that has %v registered nodes", namespace, len(nodes))
	}
	return a.Services.DeleteNamespace(namespace)
}

func (a *Server) DeleteAccessRequest(ctx context.Context, name string) error {
	if err := a.Services.DeleteAccessRequest(ctx, name); err != nil {
		return trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.AccessRequestDelete{
		Metadata: apievents.Metadata{
			Type: events.AccessRequestDeleteEvent,
			Code: events.AccessRequestDeleteCode,
		},
		UserMetadata: ClientUserMetadata(ctx),
		RequestID:    name,
	}); err != nil {
		log.WithError(err).Warn("Failed to emit access request delete event.")
	}
	return nil
}

func (a *Server) SetAccessRequestState(ctx context.Context, params types.AccessRequestUpdate) error {
	req, err := a.Services.SetAccessRequestState(ctx, params)
	if err != nil {
		return trace.Wrap(err)
	}
	event := &apievents.AccessRequestCreate{
		Metadata: apievents.Metadata{
			Type: events.AccessRequestUpdateEvent,
			Code: events.AccessRequestUpdateCode,
		},
		ResourceMetadata: apievents.ResourceMetadata{
			UpdatedBy: ClientUsername(ctx),
			Expires:   req.GetAccessExpiry(),
		},
		RequestID:    params.RequestID,
		RequestState: params.State.String(),
		Reason:       params.Reason,
		Roles:        params.Roles,
	}

	if delegator := apiutils.GetDelegator(ctx); delegator != "" {
		event.Delegator = delegator
	}

	if len(params.Annotations) > 0 {
		annotations, err := apievents.EncodeMapStrings(params.Annotations)
		if err != nil {
			log.WithError(err).Debugf("Failed to encode access request annotations.")
		} else {
			event.Annotations = annotations
		}
	}
	err = a.emitter.EmitAuditEvent(a.closeCtx, event)
	if err != nil {
		log.WithError(err).Warn("Failed to emit access request update event.")
	}
	return trace.Wrap(err)
}

// GenerateCertAuthorityCRL generates an empty CRL for the local CA of a given type.
func (a *Server) GenerateCertAuthorityCRL(ctx context.Context, caType types.CertAuthType) ([]byte, error) {
	// Generate a CRL for the current cluster CA.
	clusterName, err := a.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ca, err := a.GetCertAuthority(ctx, types.CertAuthID{
		Type:       caType,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO(awly): this will only create a CRL for an active signer.
	// If there are multiple signers (multiple HSMs), we won't have the full CRL coverage.
	// Generate a CRL per signer and return all of them separately.

	cert, signer, err := a.keyStore.GetTLSCertAndSigner(ca)
	if trace.IsNotFound(err) {
		// If there is no local TLS signer found in the host CA ActiveKeys, this
		// auth server may have a newly configured HSM and has only populated
		// local keys in the AdditionalTrustedKeys until the next CA rotation.
		// This is the only case where we should be able to get a signer from
		// AdditionalTrustedKeys but not ActiveKeys.
		cert, signer, err = a.keyStore.GetAdditionalTrustedTLSCertAndSigner(ca)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsAuthority, err := tlsca.FromCertAndSigner(cert, signer)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Empty CRL valid for 1yr.
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Minute), // 1 min in the past to account for clock skew.
		NextUpdate: time.Now().Add(365 * 24 * time.Hour),
	}
	crl, err := x509.CreateRevocationList(rand.Reader, template, tlsAuthority.Cert, tlsAuthority.Signer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return crl, nil
}

// ErrDone indicates that resource iteration is complete
var ErrDone = errors.New("done iterating")

// IterateResources loads all resources matching the provided request and passes them one by one to the provided
// callback function. To stop iteration callers may return ErrDone from the callback function, which will result in
// a nil return from IterateResources. Any other errors returned from the callback function cause iteration to stop
// and the error to be returned.
func (a *Server) IterateResources(ctx context.Context, req proto.ListResourcesRequest, f func(resource types.ResourceWithLabels) error) error {
	for {
		resp, err := a.ListResources(ctx, req)
		if err != nil {
			return trace.Wrap(err)
		}

		for _, resource := range resp.Resources {
			if err := f(resource); err != nil {
				if errors.Is(err, ErrDone) {
					return nil
				}
				return trace.Wrap(err)
			}
		}

		if resp.NextKey == "" {
			return nil
		}

		req.StartKey = resp.NextKey
	}
}

// CreateAuditStream creates audit event stream
func (a *Server) CreateAuditStream(ctx context.Context, sid session.ID) (apievents.Stream, error) {
	streamer, err := a.modeStreamer(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return streamer.CreateAuditStream(ctx, sid)
}

// ResumeAuditStream resumes the stream that has been created
func (a *Server) ResumeAuditStream(ctx context.Context, sid session.ID, uploadID string) (apievents.Stream, error) {
	streamer, err := a.modeStreamer(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return streamer.ResumeAuditStream(ctx, sid, uploadID)
}

// modeStreamer creates streamer based on the event mode
func (a *Server) modeStreamer(ctx context.Context) (events.Streamer, error) {
	recConfig, err := a.GetSessionRecordingConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// In sync mode, auth server forwards session control to the event log
	// in addition to sending them and data events to the record storage.
	if services.IsRecordSync(recConfig.GetMode()) {
		return events.NewTeeStreamer(a.streamer, a.emitter), nil
	}
	// In async mode, clients submit session control events
	// during the session in addition to writing a local
	// session recording to be uploaded at the end of the session,
	// so forwarding events here will result in duplicate events.
	return a.streamer, nil
}

// CreateSessionTracker creates a tracker resource for an active session.
func (a *Server) CreateSessionTracker(ctx context.Context, tracker types.SessionTracker) (types.SessionTracker, error) {
	// Don't allow sessions that require moderation without the enterprise feature enabled.
	for _, policySet := range tracker.GetHostPolicySets() {
		if len(policySet.RequireSessionJoin) != 0 {
			if !modules.GetModules().Features().ModeratedSessions {
				return nil, trace.AccessDenied("this Teleport cluster is not licensed for moderated sessions, please contact the cluster administrator")
			}
		}
	}

	return a.Services.CreateSessionTracker(ctx, tracker)
}

// ListResources returns paginated resources depending on the resource type..
func (a *Server) ListResources(ctx context.Context, req proto.ListResourcesRequest) (*types.ListResourcesResponse, error) {
	return a.Cache.ListResources(ctx, req)
}

func mergeKeySets(a, b types.CAKeySet) types.CAKeySet {
	newKeySet := a.Clone()
	newKeySet.SSH = append(newKeySet.SSH, b.SSH...)
	newKeySet.TLS = append(newKeySet.TLS, b.TLS...)
	newKeySet.JWT = append(newKeySet.JWT, b.JWT...)
	return newKeySet
}

// addAdditionalTrustedKeysAtomic performs an atomic CompareAndSwap to update
// the given CA with newKeys added to the AdditionalTrustedKeys
func (a *Server) addAddtionalTrustedKeysAtomic(
	ctx context.Context,
	currentCA types.CertAuthority,
	newKeys types.CAKeySet,
	needsUpdate func(types.CertAuthority) bool,
) error {
	for {
		select {
		case <-a.closeCtx.Done():
			return trace.Wrap(a.closeCtx.Err())
		default:
		}
		if !needsUpdate(currentCA) {
			return nil
		}

		newCA := currentCA.Clone()
		currentKeySet := newCA.GetAdditionalTrustedKeys()
		mergedKeySet := mergeKeySets(currentKeySet, newKeys)
		if err := newCA.SetAdditionalTrustedKeys(mergedKeySet); err != nil {
			return trace.Wrap(err)
		}

		err := a.CompareAndSwapCertAuthority(newCA, currentCA)
		if err != nil && !trace.IsCompareFailed(err) {
			return trace.Wrap(err)
		}
		if err == nil {
			// success!
			return nil
		}
		// else trace.IsCompareFailed(err) == true (CA was concurrently updated)

		currentCA, err = a.Services.GetCertAuthority(ctx, currentCA.GetID(), true)
		if err != nil {
			return trace.Wrap(err)
		}
	}
}

func newKeySet(keyStore keystore.KeyStore, caID types.CertAuthID) (types.CAKeySet, error) {
	var keySet types.CAKeySet
	switch caID.Type {
	case types.UserCA, types.HostCA:
		sshKeyPair, err := keyStore.NewSSHKeyPair()
		if err != nil {
			return keySet, trace.Wrap(err)
		}
		tlsKeyPair, err := keyStore.NewTLSKeyPair(caID.DomainName)
		if err != nil {
			return keySet, trace.Wrap(err)
		}
		keySet.SSH = append(keySet.SSH, sshKeyPair)
		keySet.TLS = append(keySet.TLS, tlsKeyPair)
	case types.DatabaseCA:
		// Database CA only contains TLS cert.
		tlsKeyPair, err := keyStore.NewTLSKeyPair(caID.DomainName)
		if err != nil {
			return keySet, trace.Wrap(err)
		}
		keySet.TLS = append(keySet.TLS, tlsKeyPair)
	case types.JWTSigner:
		jwtKeyPair, err := keyStore.NewJWTKeyPair()
		if err != nil {
			return keySet, trace.Wrap(err)
		}
		keySet.JWT = append(keySet.JWT, jwtKeyPair)
	default:
		return keySet, trace.BadParameter("unknown ca type: %s", caID.Type)
	}
	return keySet, nil
}

// ensureLocalAdditionalKeys adds additional trusted keys to the CA if they are not
// already present.
func (a *Server) ensureLocalAdditionalKeys(ctx context.Context, ca types.CertAuthority) error {
	if a.keyStore.HasLocalAdditionalKeys(ca) {
		// nothing to do
		return nil
	}

	newKeySet, err := newKeySet(a.keyStore, ca.GetID())
	if err != nil {
		return trace.Wrap(err)
	}

	err = a.addAddtionalTrustedKeysAtomic(ctx, ca, newKeySet, func(ca types.CertAuthority) bool {
		return !a.keyStore.HasLocalAdditionalKeys(ca)
	})
	if err != nil {
		return trace.Wrap(err)
	}
	log.Infof("Successfully added local additional trusted keys to %s CA.", ca.GetType())
	return nil
}

// createSelfSignedCA creates a new self-signed CA and writes it to the
// backend, with the type and clusterName given by the argument caID.
func (a *Server) createSelfSignedCA(caID types.CertAuthID) error {
	keySet, err := newKeySet(a.keyStore, caID)
	if err != nil {
		return trace.Wrap(err)
	}
	ca, err := types.NewCertAuthority(types.CertAuthoritySpecV2{
		Type:        caID.Type,
		ClusterName: caID.DomainName,
		ActiveKeys:  keySet,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	if err := a.CreateCertAuthority(ca); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// deleteUnusedKeys deletes all teleport keys held in a connected HSM for this
// auth server which are not currently used in any CAs.
func (a *Server) deleteUnusedKeys(ctx context.Context) error {
	clusterName, err := a.Services.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	var usedKeys [][]byte
	for _, caType := range types.CertAuthTypes {
		caID := types.CertAuthID{Type: caType, DomainName: clusterName.GetClusterName()}
		ca, err := a.Services.GetCertAuthority(ctx, caID, true)
		if err != nil {
			return trace.Wrap(err)
		}
		for _, keySet := range []types.CAKeySet{ca.GetActiveKeys(), ca.GetAdditionalTrustedKeys()} {
			for _, sshKeyPair := range keySet.SSH {
				usedKeys = append(usedKeys, sshKeyPair.PrivateKey)
			}
			for _, tlsKeyPair := range keySet.TLS {
				usedKeys = append(usedKeys, tlsKeyPair.Key)
			}
			for _, jwtKeyPair := range keySet.JWT {
				usedKeys = append(usedKeys, jwtKeyPair.PrivateKey)
			}
		}
	}
	return trace.Wrap(a.keyStore.DeleteUnusedKeys(usedKeys))
}

// DefaultDNSNamesForRole returns default DNS names for the specified role.
func DefaultDNSNamesForRole(role types.SystemRole) []string {
	if (types.SystemRoles{role}).IncludeAny(types.RoleAuth, types.RoleAdmin, types.RoleProxy) {
		return []string{
			"*." + constants.APIDomain,
			constants.APIDomain,
		}
	}
	return nil
}
