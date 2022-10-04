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
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
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
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
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

	if cfg.Presence == nil {
		cfg.Presence = local.NewPresenceService(cfg.Backend)
	}
	if cfg.Access == nil {
		cfg.Access = local.NewAccessService(cfg.Backend)
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
		Presence:             cfg.Presence,
		Access:               cfg.Access,
		ClusterConfiguration: cfg.ClusterConfiguration,
		Restrictions:         cfg.Restrictions,
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
	services.Access
	services.ClusterConfiguration
	services.Restrictions
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

	// limiter limits the number of active connections per client IP.
	limiter *limiter.ConnectionsLimiter

	// Emitter is events emitter, used to submit discrete events
	emitter apievents.Emitter

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

// ErrDone indicates that resource iteration is complete
var ErrDone = errors.New("done iterating")

func mergeKeySets(a, b types.CAKeySet) types.CAKeySet {
	newKeySet := a.Clone()
	newKeySet.SSH = append(newKeySet.SSH, b.SSH...)
	newKeySet.TLS = append(newKeySet.TLS, b.TLS...)
	newKeySet.JWT = append(newKeySet.JWT, b.JWT...)
	return newKeySet
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
