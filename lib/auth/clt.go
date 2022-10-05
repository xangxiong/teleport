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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/observability/tracing"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	// CurrentVersion is a current API version
	CurrentVersion = types.V2

	// MissingNamespaceError indicates that the client failed to
	// provide the namespace in the request.
	MissingNamespaceError = "missing required parameter: namespace"
)

// Client is the Auth API client. It works by connecting to auth servers
// via gRPC and HTTP.
//
// When Teleport servers connect to auth API, they usually establish an SSH
// tunnel first, and then do HTTP-over-SSH. This client is wrapped by auth.TunClient
// in lib/auth/tun.go
//
// NOTE: This client is being deprecated in favor of the gRPC Client in
// teleport/api/client. This Client should only be used internally, or for
// functionality that hasn't been ported to the new client yet.
type Client struct {
	// APIClient is used to make gRPC requests to the server
	*APIClient
	// HTTPClient is used to make http requests to the server
	*HTTPClient
}

// Make sure Client implements all the necessary methods.
var _ ClientI = &Client{}

// NewClient creates a new API client with a connection to a Teleport server.
//
// The client will use the first credentials and the given dialer. If
// no dialer is given, the first address will be used. This address must
// be an auth server address.
//
// NOTE: This client is being deprecated in favor of the gRPC Client in
// teleport/api/client. This Client should only be used internally, or for
// functionality that hasn't been ported to the new client yet.
func NewClient(cfg client.Config, params ...roundtrip.ClientParam) (*Client, error) {
	cfg.DialInBackground = true
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	apiClient, err := client.New(cfg.Context, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// apiClient configures the tls.Config, so we clone it and reuse it for http.
	tlsConfig := apiClient.Config().Clone()
	httpClient, err := NewHTTPClient(cfg, tlsConfig, params...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &Client{
		APIClient:  apiClient,
		HTTPClient: httpClient,
	}, nil
}

// APIClient is aliased here so that it can be embedded in Client.
type APIClient = client.Client

// HTTPClient is a teleport HTTP API client.
type HTTPClient struct {
	roundtrip.Client
	// transport defines the methods by which the client can reach the server.
	transport *http.Transport
	// TLS holds the TLS config for the http client.
	tls *tls.Config
}

// NewHTTPClient creates a new HTTP client with TLS authentication and the given dialer.
func NewHTTPClient(cfg client.Config, tls *tls.Config, params ...roundtrip.ClientParam) (*HTTPClient, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	dialer := cfg.Dialer
	if dialer == nil {
		if len(cfg.Addrs) == 0 {
			return nil, trace.BadParameter("no addresses to dial")
		}
		contextDialer := client.NewDialer(cfg.Context, cfg.KeepAlivePeriod, cfg.DialTimeout)
		dialer = client.ContextDialerFunc(func(ctx context.Context, network, _ string) (conn net.Conn, err error) {
			for _, addr := range cfg.Addrs {
				conn, err = contextDialer.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
			}
			// not wrapping on purpose to preserve the original error
			return nil, err
		})
	}

	// Set the next protocol. This is needed due to the Auth Server using a
	// multiplexer for protocol detection. Unless next protocol is specified
	// it will attempt to upgrade to HTTP2 and at that point there is no way
	// to distinguish between HTTP2/JSON or GPRC.
	tls.NextProtos = []string{teleport.HTTPNextProtoTLS}
	// Configure ALPN SNI direct dial TLS routing information used by ALPN SNI proxy in order to
	// dial auth service without using SSH tunnels.
	tls = client.ConfigureALPN(tls, cfg.ALPNSNIAuthDialClusterName)

	transport := &http.Transport{
		// notice that below roundtrip.Client is passed
		// teleport.APIDomain as an address for the API server, this is
		// to make sure client verifies the DNS name of the API server and
		// custom DialContext overrides this DNS name to the real address.
		// In addition this dialer tries multiple addresses if provided
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: apidefaults.DefaultDialTimeout,
		TLSClientConfig:       tls,

		// Increase the size of the connection pool. This substantially improves the
		// performance of Teleport under load as it reduces the number of TLS
		// handshakes performed.
		MaxIdleConns:        defaults.HTTPMaxIdleConns,
		MaxIdleConnsPerHost: defaults.HTTPMaxIdleConnsPerHost,

		// Limit the total number of connections to the Auth Server. Some hosts allow a low
		// number of connections per process (ulimit) to a host. This is a problem for
		// enhanced session recording auditing which emits so many events to the
		// Audit Log (using the Auth Client) that the connection pool often does not
		// have a free connection to return, so just opens a new one. This quickly
		// leads to hitting the OS limit and the client returning out of file
		// descriptors error.
		MaxConnsPerHost: defaults.HTTPMaxConnsPerHost,

		// IdleConnTimeout defines the maximum amount of time before idle connections
		// are closed. Leaving this unset will lead to connections open forever and
		// will cause memory leaks in a long running process.
		IdleConnTimeout: defaults.HTTPIdleTimeout,
	}

	cb, err := breaker.New(cfg.CircuitBreakerConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clientParams := append(
		[]roundtrip.ClientParam{
			roundtrip.HTTPClient(&http.Client{
				Timeout: defaults.HTTPRequestTimeout,
				Transport: otelhttp.NewTransport(
					breaker.NewRoundTripper(cb, transport),
					otelhttp.WithSpanNameFormatter(tracing.HTTPTransportFormatter),
				),
			}),
			roundtrip.SanitizerEnabled(true),
		},
		params...,
	)

	// Since the client uses a custom dialer and SNI is used for TLS handshake, the address
	// used here is arbitrary as it just needs to be set to pass http request validation.
	httpClient, err := roundtrip.NewClient("https://"+constants.APIDomain, CurrentVersion, clientParams...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &HTTPClient{
		Client:    *httpClient,
		transport: transport,
		tls:       tls,
	}, nil
}

// Close closes the HTTP client connection to the auth server.
func (c *HTTPClient) Close() {
	c.transport.CloseIdleConnections()
}

// TLSConfig returns the HTTP client's TLS config.
func (c *HTTPClient) TLSConfig() *tls.Config {
	return c.tls
}

// GetTransport returns the HTTP client's transport.
func (c *HTTPClient) GetTransport() *http.Transport {
	return c.transport
}

// ClientTimeout sets idle and dial timeouts of the HTTP transport
// used by the client.
func ClientTimeout(timeout time.Duration) roundtrip.ClientParam {
	return func(c *roundtrip.Client) error {
		transport, ok := (c.HTTPClient().Transport).(*http.Transport)
		if !ok {
			return nil
		}
		transport.IdleConnTimeout = timeout
		transport.ResponseHeaderTimeout = timeout
		return nil
	}
}

// PostJSON is a generic method that issues http POST request to the server
func (c *Client) PostJSON(ctx context.Context, endpoint string, val interface{}) (*roundtrip.Response, error) {
	return httplib.ConvertResponse(c.Client.PostJSON(ctx, endpoint, val))
}

// PutJSON is a generic method that issues http PUT request to the server
func (c *Client) PutJSON(ctx context.Context, endpoint string, val interface{}) (*roundtrip.Response, error) {
	return httplib.ConvertResponse(c.Client.PutJSON(ctx, endpoint, val))
}

// PostForm is a generic method that issues http POST request to the server
func (c *Client) PostForm(ctx context.Context, endpoint string, vals url.Values, files ...roundtrip.File) (*roundtrip.Response, error) {
	return httplib.ConvertResponse(c.Client.PostForm(ctx, endpoint, vals, files...))
}

// Get issues http GET request to the server
func (c *Client) Get(ctx context.Context, u string, params url.Values) (*roundtrip.Response, error) {
	return httplib.ConvertResponse(c.Client.Get(ctx, u, params))
}

// Delete issues http Delete Request to the server
func (c *Client) Delete(ctx context.Context, u string) (*roundtrip.Response, error) {
	return httplib.ConvertResponse(c.Client.Delete(ctx, u))
}

// GetSession returns a session by ID
func (c *Client) GetSession(ctx context.Context, namespace string, id session.ID) (*session.Session, error) {
	if namespace == "" {
		return nil, trace.BadParameter(MissingNamespaceError)
	}
	// saving extra round-trip
	if err := id.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	out, err := c.Get(ctx, c.Endpoint("namespaces", namespace, "sessions", string(id)), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var sess *session.Session
	if err := json.Unmarshal(out.Bytes(), &sess); err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}

// DeleteSession removes an active session from the backend.
func (c *Client) DeleteSession(ctx context.Context, namespace string, id session.ID) error {
	if namespace == "" {
		return trace.BadParameter(MissingNamespaceError)
	}
	_, err := c.Delete(ctx, c.Endpoint("namespaces", namespace, "sessions", string(id)))
	return trace.Wrap(err)
}

// CreateSession creates new session
func (c *Client) CreateSession(ctx context.Context, sess session.Session) error {
	if sess.Namespace == "" {
		return trace.BadParameter(MissingNamespaceError)
	}
	_, err := c.PostJSON(ctx, c.Endpoint("namespaces", sess.Namespace, "sessions"), createSessionReq{Session: sess})
	return trace.Wrap(err)
}

// UpdateSession updates existing session
func (c *Client) UpdateSession(ctx context.Context, req session.UpdateRequest) error {
	if err := req.Check(); err != nil {
		return trace.Wrap(err)
	}
	_, err := c.PutJSON(ctx, c.Endpoint("namespaces", req.Namespace, "sessions", string(req.ID)), updateSessionReq{Update: req})
	return trace.Wrap(err)
}

func (c *Client) Close() error {
	c.HTTPClient.Close()
	return c.APIClient.Close()
}

// RotateExternalCertAuthority rotates external certificate authority,
// this method is used to update only public keys and certificates of the
// the certificate authorities of trusted clusters.
func (c *Client) RotateExternalCertAuthority(ctx context.Context, ca types.CertAuthority) error {
	if err := services.ValidateCertAuthority(ca); err != nil {
		return trace.Wrap(err)
	}
	data, err := services.MarshalCertAuthority(ca)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = c.PostJSON(ctx, c.Endpoint("authorities", string(ca.GetType()), "rotate", "external"),
		&rotateExternalCertAuthorityRawReq{CA: data})
	return trace.Wrap(err)
}

// UpsertCertAuthority updates or inserts new cert authority
func (c *Client) UpsertCertAuthority(ca types.CertAuthority) error {
	if err := services.ValidateCertAuthority(ca); err != nil {
		return trace.Wrap(err)
	}
	data, err := services.MarshalCertAuthority(ca)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = c.PostJSON(context.TODO(), c.Endpoint("authorities", string(ca.GetType())),
		&upsertCertAuthorityRawReq{CA: data})
	return trace.Wrap(err)
}

// CompareAndSwapCertAuthority updates existing cert authority if the existing cert authority
// value matches the value stored in the backend.
func (c *Client) CompareAndSwapCertAuthority(new, existing types.CertAuthority) error {
	return trace.BadParameter("this function is not supported on the client")
}

// GetCertAuthorities returns a list of certificate authorities
func (c *Client) GetCertAuthorities(ctx context.Context, caType types.CertAuthType, loadKeys bool, opts ...services.MarshalOption) ([]types.CertAuthority, error) {
	if err := caType.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	out, err := c.Get(ctx, c.Endpoint("authorities", string(caType)), url.Values{
		"load_keys": []string{fmt.Sprintf("%t", loadKeys)},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		return nil, err
	}
	re := make([]types.CertAuthority, len(items))
	for i, raw := range items {
		ca, err := services.UnmarshalCertAuthority(raw)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		re[i] = ca
	}
	return re, nil
}

// GetCertAuthority returns certificate authority by given id. Parameter loadSigningKeys
// controls if signing keys are loaded
func (c *Client) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadSigningKeys bool, opts ...services.MarshalOption) (types.CertAuthority, error) {
	if err := id.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	out, err := c.Get(ctx, c.Endpoint("authorities", string(id.Type), id.DomainName), url.Values{
		"load_keys": []string{fmt.Sprintf("%t", loadSigningKeys)},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalCertAuthority(out.Bytes())
}

// DeleteCertAuthority deletes cert authority by ID
func (c *Client) DeleteCertAuthority(id types.CertAuthID) error {
	if err := id.Check(); err != nil {
		return trace.Wrap(err)
	}
	_, err := c.Delete(context.TODO(), c.Endpoint("authorities", string(id.Type), id.DomainName))
	return trace.Wrap(err)
}

// ActivateCertAuthority not implemented: can only be called locally.
func (c *Client) ActivateCertAuthority(id types.CertAuthID) error {
	return trace.NotImplemented(notImplementedMessage)
}

// DeactivateCertAuthority not implemented: can only be called locally.
func (c *Client) DeactivateCertAuthority(id types.CertAuthID) error {
	return trace.NotImplemented(notImplementedMessage)
}

// RegisterUsingToken calls the auth service API to register a new node using a registration token
// which was previously issued via GenerateToken.
func (c *Client) RegisterUsingToken(ctx context.Context, req *types.RegisterUsingTokenRequest) (*proto.Certs, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	out, err := c.PostJSON(ctx, c.Endpoint("tokens", "register"), req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var certs proto.Certs
	if err := json.Unmarshal(out.Bytes(), &certs); err != nil {
		return nil, trace.Wrap(err)
	}

	return &certs, nil
}

// KeepAliveServer not implemented: can only be called locally.
func (c *Client) KeepAliveServer(ctx context.Context, keepAlive types.KeepAlive) error {
	return trace.BadParameter("not implemented, use StreamKeepAlives instead")
}

// UpsertReverseTunnel is used by admins to create a new reverse tunnel
// to the remote proxy to bypass firewall restrictions
func (c *Client) UpsertReverseTunnel(tunnel types.ReverseTunnel) error {
	data, err := services.MarshalReverseTunnel(tunnel)
	if err != nil {
		return trace.Wrap(err)
	}
	args := &upsertReverseTunnelRawReq{
		ReverseTunnel: data,
	}
	_, err = c.PostJSON(context.TODO(), c.Endpoint("reversetunnels"), args)
	return trace.Wrap(err)
}

// GetReverseTunnels returns the list of created reverse tunnels
func (c *Client) GetReverseTunnels(ctx context.Context, opts ...services.MarshalOption) ([]types.ReverseTunnel, error) {
	out, err := c.Get(ctx, c.Endpoint("reversetunnels"), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		return nil, trace.Wrap(err)
	}
	tunnels := make([]types.ReverseTunnel, len(items))
	for i, raw := range items {
		tunnel, err := services.UnmarshalReverseTunnel(raw)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		tunnels[i] = tunnel
	}
	return tunnels, nil
}

// UpsertTunnelConnection upserts tunnel connection
func (c *Client) UpsertTunnelConnection(conn types.TunnelConnection) error {
	data, err := services.MarshalTunnelConnection(conn)
	if err != nil {
		return trace.Wrap(err)
	}
	args := &upsertTunnelConnectionRawReq{
		TunnelConnection: data,
	}
	_, err = c.PostJSON(context.TODO(), c.Endpoint("tunnelconnections"), args)
	return trace.Wrap(err)
}

// DeleteTunnelConnection deletes tunnel connection by name
func (c *Client) DeleteTunnelConnection(clusterName string, connName string) error {
	if clusterName == "" {
		return trace.BadParameter("missing parameter cluster name")
	}
	if connName == "" {
		return trace.BadParameter("missing parameter connection name")
	}
	_, err := c.Delete(context.TODO(), c.Endpoint("tunnelconnections", clusterName, connName))
	return trace.Wrap(err)
}

// GetRemoteClusters returns a list of remote clusters
func (c *Client) GetRemoteClusters(opts ...services.MarshalOption) ([]types.RemoteCluster, error) {
	out, err := c.Get(context.TODO(), c.Endpoint("remoteclusters"), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		return nil, trace.Wrap(err)
	}
	conns := make([]types.RemoteCluster, len(items))
	for i, raw := range items {
		conn, err := services.UnmarshalRemoteCluster(raw)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		conns[i] = conn
	}
	return conns, nil
}

// GetRemoteCluster returns a remote cluster by name
func (c *Client) GetRemoteCluster(clusterName string) (types.RemoteCluster, error) {
	if clusterName == "" {
		return nil, trace.BadParameter("missing cluster name")
	}
	out, err := c.Get(context.TODO(), c.Endpoint("remoteclusters", clusterName), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalRemoteCluster(out.Bytes())
}

// GetProxies returns the list of auth servers registered in the cluster.
func (c *Client) GetProxies() ([]types.Server, error) {
	out, err := c.Get(context.TODO(), c.Endpoint("proxies"), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		return nil, trace.Wrap(err)
	}
	re := make([]types.Server, len(items))
	for i, raw := range items {
		server, err := services.UnmarshalServer(raw, types.KindProxy)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		re[i] = server
	}
	return re, nil
}

// GenerateHostCert takes the public key in the Open SSH “authorized_keys“
// plain text format, signs it using Host Certificate Authority private key and returns the
// resulting certificate.
func (c *Client) GenerateHostCert(
	key []byte, hostID, nodeName string, principals []string, clusterName string, role types.SystemRole, ttl time.Duration,
) ([]byte, error) {
	out, err := c.PostJSON(context.TODO(), c.Endpoint("ca", "host", "certs"),
		generateHostCertReq{
			Key:         key,
			HostID:      hostID,
			NodeName:    nodeName,
			Principals:  principals,
			ClusterName: clusterName,
			Roles:       types.SystemRoles{role},
			TTL:         ttl,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var cert string
	if err := json.Unmarshal(out.Bytes(), &cert); err != nil {
		return nil, err
	}

	return []byte(cert), nil
}

// GetNamespace returns namespace by name
func (c *Client) GetNamespace(name string) (*types.Namespace, error) {
	if name == "" {
		return nil, trace.BadParameter("missing namespace name")
	}
	out, err := c.Get(context.TODO(), c.Endpoint("namespaces", name), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalNamespace(out.Bytes())
}

// GetClusterName returns a cluster name
func (c *Client) GetClusterName(opts ...services.MarshalOption) (types.ClusterName, error) {
	out, err := c.Get(context.TODO(), c.Endpoint("configuration", "name"), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cn, err := services.UnmarshalClusterName(out.Bytes())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return cn, err
}

// GetStaticTokens returns a list of static register tokens
func (c *Client) GetStaticTokens() (types.StaticTokens, error) {
	out, err := c.Get(context.TODO(), c.Endpoint("configuration", "static_tokens"), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	st, err := services.UnmarshalStaticTokens(out.Bytes())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return st, err
}

// GetClusterNetworkingConfig gets cluster networking configuration.
func (c *Client) GetClusterNetworkingConfig(ctx context.Context, opts ...services.MarshalOption) (types.ClusterNetworkingConfig, error) {
	return c.APIClient.GetClusterNetworkingConfig(ctx)
}

// GetSessionRecordingConfig gets session recording configuration.
func (c *Client) GetSessionRecordingConfig(ctx context.Context, opts ...services.MarshalOption) (types.SessionRecordingConfig, error) {
	return c.APIClient.GetSessionRecordingConfig(ctx)
}

// IdentityService manages identities and users
type IdentityService interface {
	// GenerateToken creates a special provisioning token for a new SSH server
	// that is valid for ttl period seconds.
	//
	// This token is used by SSH server to authenticate with Auth server
	// and get signed certificate and private key from the auth server.
	//
	// If token is not supplied, it will be auto generated and returned.
	// If TTL is not supplied, token will be valid until removed.
	GenerateToken(ctx context.Context, req *proto.GenerateTokenRequest) (string, error)

	// GenerateHostCert takes the public key in the Open SSH ``authorized_keys``
	// plain text format, signs it using Host Certificate Authority private key and returns the
	// resulting certificate.
	GenerateHostCert(key []byte, hostID, nodeName string, principals []string, clusterName string, role types.SystemRole, ttl time.Duration) ([]byte, error)

	// GenerateUserSingleUseCerts is like GenerateUserCerts but issues a
	// certificate for a single session
	// (https://github.com/gravitational/teleport/blob/3a1cf9111c2698aede2056513337f32bfc16f1f1/rfd/0014-session-2FA.md#sessions).
	GenerateUserSingleUseCerts(ctx context.Context) (proto.AuthService_GenerateUserSingleUseCertsClient, error)

	// MaintainSessionPresence establishes a channel used to continuously verify the presence for a session.
	MaintainSessionPresence(ctx context.Context) (proto.AuthService_MaintainSessionPresenceClient, error)
}

// ProvisioningService is a service in control
// of adding new nodes, auth servers and proxies to the cluster
type ProvisioningService interface {
	// GetTokens returns a list of active invitation tokens for nodes and users
	GetTokens(ctx context.Context) (tokens []types.ProvisionToken, err error)

	// GetToken returns provisioning token
	GetToken(ctx context.Context, token string) (types.ProvisionToken, error)

	// UpsertToken adds provisioning tokens for the auth server
	UpsertToken(ctx context.Context, token types.ProvisionToken) error

	// CreateToken creates a new provision token for the auth server
	CreateToken(ctx context.Context, token types.ProvisionToken) error

	// RegisterUsingToken calls the auth service API to register a new node via registration token
	// which has been previously issued via GenerateToken
	RegisterUsingToken(ctx context.Context, req *types.RegisterUsingTokenRequest) (*proto.Certs, error)
}

// ClientI is a client to Auth service
type ClientI interface {
	IdentityService
	ProvisioningService
	services.Trust
	events.IAuditLog
	services.Presence
	services.Access
	services.DynamicAccess
	session.Service
	services.Status
	services.ClusterConfiguration
	services.SessionTrackerService
	types.Events

	// NewKeepAliver returns a new instance of keep aliver
	NewKeepAliver(ctx context.Context) (types.KeepAliver, error)

	// RotateExternalCertAuthority rotates external certificate authority,
	// this method is used to update only public keys and certificates of the
	// the certificate authorities of trusted clusters.
	RotateExternalCertAuthority(ctx context.Context, ca types.CertAuthority) error

	// GetDomainName returns auth server cluster name
	GetDomainName(ctx context.Context) (string, error)

	// GetClusterCACert returns the PEM-encoded TLS certs for the local cluster.
	// If the cluster has multiple TLS certs, they will all be concatenated.
	GetClusterCACert(ctx context.Context) (*proto.GetClusterCACertResponse, error)

	// GenerateHostCerts generates new host certificates (signed
	// by the host certificate authority) for a node
	GenerateHostCerts(context.Context, *proto.HostCertsRequest) (*proto.Certs, error)

	// Ping gets basic info about the auth server.
	Ping(ctx context.Context) (proto.PingResponse, error)
}
