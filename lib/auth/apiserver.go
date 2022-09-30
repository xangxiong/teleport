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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/plugin"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/julienschmidt/httprouter"
)

type APIConfig struct {
	PluginRegistry plugin.Registry
	AuthServer     *Server
	SessionService session.Service
	AuditLog       events.IAuditLog
	Authorizer     Authorizer
	Emitter        apievents.Emitter
	// KeepAlivePeriod defines period between keep alives
	KeepAlivePeriod time.Duration
	// KeepAliveCount specifies amount of missed keep alives
	// to wait for until declaring connection as broken
	KeepAliveCount int
	// MetadataGetter retrieves additional metadata about session uploads.
	// Will be nil if audit logging is not enabled.
	MetadataGetter events.UploadMetadataGetter
}

// CheckAndSetDefaults checks and sets default values
func (a *APIConfig) CheckAndSetDefaults() error {
	if a.KeepAlivePeriod == 0 {
		a.KeepAlivePeriod = apidefaults.ServerKeepAliveTTL()
	}
	if a.KeepAliveCount == 0 {
		a.KeepAliveCount = apidefaults.KeepAliveCountMax
	}
	return nil
}

// APIServer implements http API server for AuthServer interface
type APIServer struct {
	APIConfig
	httprouter.Router
	clockwork.Clock
}

// NewAPIServer returns a new instance of APIServer HTTP handler
func NewAPIServer(config *APIConfig) (http.Handler, error) {
	srv := APIServer{
		APIConfig: *config,
		Clock:     clockwork.NewRealClock(),
	}
	srv.Router = *httprouter.New()
	srv.Router.UseRawPath = true

	// Operations on certificate authorities
	srv.GET("/:version/domain", srv.withAuth(srv.getDomainName))    // DELETE IN 11.0.0 REST method replaced by gRPC
	srv.GET("/:version/cacert", srv.withAuth(srv.getClusterCACert)) // DELETE IN 11.0.0 REST method replaced by gRPC

	srv.POST("/:version/authorities/:type", srv.withAuth(srv.upsertCertAuthority))
	srv.POST("/:version/authorities/:type/rotate", srv.withAuth(srv.rotateCertAuthority))
	srv.POST("/:version/authorities/:type/rotate/external", srv.withAuth(srv.rotateExternalCertAuthority))
	srv.DELETE("/:version/authorities/:type/:domain", srv.withAuth(srv.deleteCertAuthority))
	srv.GET("/:version/authorities/:type/:domain", srv.withAuth(srv.getCertAuthority))
	srv.GET("/:version/authorities/:type", srv.withAuth(srv.getCertAuthorities))

	// Generating certificates for user and host authorities
	srv.POST("/:version/ca/host/certs", srv.withAuth(srv.generateHostCert))

	// Servers and presence heartbeat
	srv.POST("/:version/namespaces/:namespace/nodes/keepalive", srv.withAuth(srv.keepAliveNode))
	srv.POST("/:version/authservers", srv.withAuth(srv.upsertAuthServer))
	srv.GET("/:version/authservers", srv.withAuth(srv.getAuthServers))
	srv.POST("/:version/proxies", srv.withAuth(srv.upsertProxy))
	srv.GET("/:version/proxies", srv.withAuth(srv.getProxies))
	srv.DELETE("/:version/proxies", srv.withAuth(srv.deleteAllProxies))
	srv.DELETE("/:version/proxies/:name", srv.withAuth(srv.deleteProxy))
	srv.POST("/:version/tunnelconnections", srv.withAuth(srv.upsertTunnelConnection))
	srv.GET("/:version/tunnelconnections/:cluster", srv.withAuth(srv.getTunnelConnections))
	srv.GET("/:version/tunnelconnections", srv.withAuth(srv.getAllTunnelConnections))
	srv.DELETE("/:version/tunnelconnections/:cluster/:conn", srv.withAuth(srv.deleteTunnelConnection))
	srv.DELETE("/:version/tunnelconnections/:cluster", srv.withAuth(srv.deleteTunnelConnections))
	srv.DELETE("/:version/tunnelconnections", srv.withAuth(srv.deleteAllTunnelConnections))

	// Remote clusters
	srv.POST("/:version/remoteclusters", srv.withAuth(srv.createRemoteCluster))
	srv.GET("/:version/remoteclusters/:cluster", srv.withAuth(srv.getRemoteCluster))
	srv.GET("/:version/remoteclusters", srv.withAuth(srv.getRemoteClusters))
	srv.DELETE("/:version/remoteclusters/:cluster", srv.withAuth(srv.deleteRemoteCluster))
	srv.DELETE("/:version/remoteclusters", srv.withAuth(srv.deleteAllRemoteClusters))

	// Reverse tunnels
	srv.POST("/:version/reversetunnels", srv.withAuth(srv.upsertReverseTunnel))
	srv.GET("/:version/reversetunnels", srv.withAuth(srv.getReverseTunnels))
	srv.DELETE("/:version/reversetunnels/:domain", srv.withAuth(srv.deleteReverseTunnel))

	// Tokens
	srv.POST("/:version/tokens", srv.withAuth(srv.generateToken))
	srv.POST("/:version/tokens/register/auth", srv.withAuth(srv.registerNewAuthServer))

	// Active sessions
	srv.GET("/:version/namespaces/:namespace/sessions/:id/stream", srv.withAuth(srv.getSessionChunk))
	srv.GET("/:version/namespaces/:namespace/sessions/:id/events", srv.withAuth(srv.getSessionEvents))

	// Namespaces
	srv.POST("/:version/namespaces", srv.withAuth(srv.upsertNamespace))
	srv.GET("/:version/namespaces", srv.withAuth(srv.getNamespaces))
	srv.GET("/:version/namespaces/:namespace", srv.withAuth(srv.getNamespace))
	srv.DELETE("/:version/namespaces/:namespace", srv.withAuth(srv.deleteNamespace))

	// cluster configuration
	srv.GET("/:version/configuration/name", srv.withAuth(srv.getClusterName))
	srv.POST("/:version/configuration/name", srv.withAuth(srv.setClusterName))
	srv.GET("/:version/configuration/static_tokens", srv.withAuth(srv.getStaticTokens))
	srv.DELETE("/:version/configuration/static_tokens", srv.withAuth(srv.deleteStaticTokens))
	srv.POST("/:version/configuration/static_tokens", srv.withAuth(srv.setStaticTokens))

	// Audit logs AKA events
	srv.GET("/:version/events", srv.withAuth(srv.searchEvents))
	srv.GET("/:version/events/session", srv.withAuth(srv.searchSessionEvents))

	if config.PluginRegistry != nil {
		if err := config.PluginRegistry.RegisterAuthWebHandlers(&srv); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return httplib.RewritePaths(&srv.Router,
		httplib.Rewrite("/v1/nodes", "/v1/namespaces/default/nodes"),
		httplib.Rewrite("/v1/sessions", "/v1/namespaces/default/sessions"),
		httplib.Rewrite("/v1/sessions/([^/]+)/(.*)", "/v1/namespaces/default/sessions/$1/$2"),
	), nil
}

// HandlerWithAuthFunc is http handler with passed auth context
type HandlerWithAuthFunc func(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error)

func (s *APIServer) withAuth(handler HandlerWithAuthFunc) httprouter.Handle {
	const accessDeniedMsg = "auth API: access denied "
	return httplib.MakeHandler(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
		// HTTPS server expects auth context to be set by the auth middleware
		authContext, err := s.Authorizer.Authorize(r.Context())
		if err != nil {
			// propagate connection problem error so we can differentiate
			// between connection failed and access denied
			if trace.IsConnectionProblem(err) {
				return nil, trace.ConnectionProblem(err, "[07] failed to connect to the database")
			} else if trace.IsAccessDenied(err) {
				// don't print stack trace, just log the warning
				log.Warn(err)
			} else {
				log.Warn(trace.DebugReport(err))
			}

			return nil, trace.AccessDenied(accessDeniedMsg + "[00]")
		}
		auth := &ServerWithRoles{
			authServer: s.AuthServer,
			context:    *authContext,
			sessions:   s.SessionService,
			alog:       s.AuthServer,
		}
		version := p.ByName("version")
		if version == "" {
			return nil, trace.BadParameter("missing version")
		}
		return handler(auth, w, r, p, version)
	})
}

type upsertServerRawReq struct {
	Server json.RawMessage `json:"server"`
	TTL    time.Duration   `json:"ttl"`
}

// upsertServer is a common utility function
func (s *APIServer) upsertServer(auth services.Presence, role types.SystemRole, r *http.Request, p httprouter.Params) (interface{}, error) {
	var req upsertServerRawReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	var kind string
	switch role {
	case types.RoleNode:
		kind = types.KindNode
	case types.RoleAuth:
		kind = types.KindAuthServer
	case types.RoleProxy:
		kind = types.KindProxy
	default:
		return nil, trace.BadParameter("upsertServer with unknown role: %q", role)
	}
	server, err := services.UnmarshalServer(req.Server, kind)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// if server sent "local" IP address to us, replace the ip/host part with the remote address we see
	// on the socket, but keep the original port:
	server.SetAddr(utils.ReplaceLocalhost(server.GetAddr(), r.RemoteAddr))
	if req.TTL != 0 {
		server.SetExpiry(s.Now().UTC().Add(req.TTL))
	}
	switch role {
	case types.RoleNode:
		namespace := p.ByName("namespace")
		if !types.IsValidNamespace(namespace) {
			return nil, trace.BadParameter("invalid namespace %q", namespace)
		}
		server.SetNamespace(namespace)
		handle, err := auth.UpsertNode(r.Context(), server)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return handle, nil
	case types.RoleAuth:
		if err := auth.UpsertAuthServer(server); err != nil {
			return nil, trace.Wrap(err)
		}
	case types.RoleProxy:
		if err := auth.UpsertProxy(server); err != nil {
			return nil, trace.Wrap(err)
		}
	default:
		return nil, trace.BadParameter("unknown server role %q", role)
	}
	return message("ok"), nil
}

// keepAliveNode updates node TTL in the backend
func (s *APIServer) keepAliveNode(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var handle types.KeepAlive
	if err := httplib.ReadJSON(r, &handle); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.KeepAliveServer(r.Context(), handle); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// upsertProxy is called by remote SSH nodes when they ping back into the auth service
func (s *APIServer) upsertProxy(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	return s.upsertServer(auth, types.RoleProxy, r, p)
}

// getProxies returns registered proxies
func (s *APIServer) getProxies(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	servers, err := auth.GetProxies()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return marshalServers(servers, version)
}

// deleteAllProxies deletes all proxies
func (s *APIServer) deleteAllProxies(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteAllProxies()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// deleteProxy deletes proxy
func (s *APIServer) deleteProxy(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	name := p.ByName("name")
	if name == "" {
		return nil, trace.BadParameter("missing proxy name")
	}
	err := auth.DeleteProxy(name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// upsertAuthServer is called by remote Auth servers when they ping back into the auth service
func (s *APIServer) upsertAuthServer(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	return s.upsertServer(auth, types.RoleAuth, r, p)
}

// getAuthServers returns registered auth servers
func (s *APIServer) getAuthServers(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	servers, err := auth.GetAuthServers()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return marshalServers(servers, version)
}

func marshalServers(servers []types.Server, version string) (interface{}, error) {
	items := make([]json.RawMessage, len(servers))
	for i, server := range servers {
		data, err := services.MarshalServer(server, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		items[i] = data
	}
	return items, nil
}

type upsertReverseTunnelRawReq struct {
	ReverseTunnel json.RawMessage `json:"reverse_tunnel"`
	TTL           time.Duration   `json:"ttl"`
}

// upsertReverseTunnel is called by admin to create a reverse tunnel to remote proxy
func (s *APIServer) upsertReverseTunnel(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req upsertReverseTunnelRawReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	tun, err := services.UnmarshalReverseTunnel(req.ReverseTunnel)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := services.ValidateReverseTunnel(tun); err != nil {
		return nil, trace.Wrap(err)
	}
	if req.TTL != 0 {
		tun.SetExpiry(s.Now().UTC().Add(req.TTL))
	}
	if err := auth.UpsertReverseTunnel(tun); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// getReverseTunnels returns a list of reverse tunnels
func (s *APIServer) getReverseTunnels(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	reverseTunnels, err := auth.GetReverseTunnels(r.Context())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]json.RawMessage, len(reverseTunnels))
	for i, tunnel := range reverseTunnels {
		data, err := services.MarshalReverseTunnel(tunnel, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		items[i] = data
	}
	return items, nil
}

// deleteReverseTunnel deletes reverse tunnel
func (s *APIServer) deleteReverseTunnel(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	domainName := p.ByName("domain")
	err := auth.DeleteReverseTunnel(domainName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message(fmt.Sprintf("reverse tunnel %v deleted", domainName)), nil
}

type WebSessionReq struct {
	// User is the user name associated with the session id.
	User string `json:"user"`
	// PrevSessionID is the id of current session.
	PrevSessionID string `json:"prev_session_id"`
	// AccessRequestID is an optional field that holds the id of an approved access request.
	AccessRequestID string `json:"access_request_id"`
	// Switchback is a flag to indicate if user is wanting to switchback from an assumed role
	// back to their default role.
	Switchback bool `json:"switchback"`
	// ReloadUser is a flag to indicate if user needs to be refetched from the backend
	// to apply new user changes e.g. user traits were updated.
	ReloadUser bool `json:"reload_user"`
}

type checkPasswordReq struct {
	Password string `json:"password"`
	OTPToken string `json:"otp_token"`
}

func rawMessage(data []byte, err error) (interface{}, error) {
	if err != nil {
		return nil, trace.Wrap(err)
	}
	m := json.RawMessage(data)
	return &m, nil
}

type generateHostCertReq struct {
	Key         []byte            `json:"key"`
	HostID      string            `json:"hostname"`
	NodeName    string            `json:"node_name"`
	Principals  []string          `json:"principals"`
	ClusterName string            `json:"auth_domain"`
	Roles       types.SystemRoles `json:"roles"`
	TTL         time.Duration     `json:"ttl"`
}

func (s *APIServer) generateHostCert(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
	var req *generateHostCertReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	if len(req.Roles) != 1 {
		return nil, trace.BadParameter("exactly one system role is required")
	}

	cert, err := auth.GenerateHostCert(req.Key, req.HostID, req.NodeName, req.Principals, req.ClusterName, req.Roles[0], req.TTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return string(cert), nil
}

// DELETE IN 11.0.0
func (s *APIServer) generateToken(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
	var req proto.GenerateTokenRequest
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	token, err := auth.GenerateToken(r.Context(), &req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return token, nil
}

type registerNewAuthServerReq struct {
	Token string `json:"token"`
}

func (s *APIServer) registerNewAuthServer(auth ClientI, w http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (interface{}, error) {
	var req *registerNewAuthServerReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	err := auth.RegisterNewAuthServer(r.Context(), req.Token)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

func (s *APIServer) rotateCertAuthority(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req RotateRequest
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.RotateCertAuthority(r.Context(), req); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

type upsertCertAuthorityRawReq struct {
	CA  json.RawMessage `json:"ca"`
	TTL time.Duration   `json:"ttl"`
}

func (s *APIServer) upsertCertAuthority(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req *upsertCertAuthorityRawReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	ca, err := services.UnmarshalCertAuthority(req.CA)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if req.TTL != 0 {
		ca.SetExpiry(s.Now().UTC().Add(req.TTL))
	}
	if err = services.ValidateCertAuthority(ca); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.UpsertCertAuthority(ca); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

type rotateExternalCertAuthorityRawReq struct {
	CA json.RawMessage `json:"ca"`
}

func (s *APIServer) rotateExternalCertAuthority(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req rotateExternalCertAuthorityRawReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	ca, err := services.UnmarshalCertAuthority(req.CA)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.RotateExternalCertAuthority(r.Context(), ca); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

func (s *APIServer) getCertAuthorities(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	loadKeys, _, err := httplib.ParseBool(r.URL.Query(), "load_keys")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := auth.GetCertAuthorities(r.Context(), types.CertAuthType(p.ByName("type")), loadKeys)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]json.RawMessage, len(certs))
	for i, cert := range certs {
		data, err := services.MarshalCertAuthority(cert, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		items[i] = data
	}
	return items, nil
}

func (s *APIServer) getCertAuthority(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	loadKeys, _, err := httplib.ParseBool(r.URL.Query(), "load_keys")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	id := types.CertAuthID{
		Type:       types.CertAuthType(p.ByName("type")),
		DomainName: p.ByName("domain"),
	}
	ca, err := auth.GetCertAuthority(r.Context(), id, loadKeys)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rawMessage(services.MarshalCertAuthority(ca, services.WithVersion(version), services.PreserveResourceID()))
}

// Replaced with gRPC endpoint
// DELETE IN 11.0.0
func (s *APIServer) getDomainName(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	domain, err := auth.GetDomainName(r.Context())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return domain, nil
}

// deprecatedLocalCAResponse contains the concatenated PEM-encoded TLS certs for
// the local cluster's Host CA
// DELETE IN 11.0.0
type deprecatedLocalCAResponse struct {
	// TLSCA is a PEM-encoded TLS certificate authority.
	TLSCA []byte `json:"tls_ca"`
}

// getClusterCACert returns the PEM-encoded TLS certs for the local cluster
// without signing keys. If the cluster has multiple TLS certs, they will all
// be appended.
// DELETE IN 11.0.0
func (s *APIServer) getClusterCACert(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	localCA, err := auth.GetClusterCACert(r.Context())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return deprecatedLocalCAResponse{
		TLSCA: localCA.TLSCA,
	}, nil
}

func (s *APIServer) deleteCertAuthority(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	id := types.CertAuthID{
		DomainName: p.ByName("domain"),
		Type:       types.CertAuthType(p.ByName("type")),
	}
	if err := auth.DeleteCertAuthority(id); err != nil {
		return nil, trace.Wrap(err)
	}
	return message(fmt.Sprintf("cert '%v' deleted", id)), nil
}

type createSessionReq struct {
	Session session.Session `json:"session"`
}

type updateSessionReq struct {
	Update session.UpdateRequest `json:"update"`
}

// HTTP GET /:version/events?query
//
// Query fields:
//
//		'from'  : time filter in RFC3339 format
//		'to'    : time filter in RFC3339 format
//	 ...     : other fields are passed directly to the audit backend
func (s *APIServer) searchEvents(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var err error
	to := time.Now().In(time.UTC)
	from := to.AddDate(0, -1, 0) // one month ago
	query := r.URL.Query()
	// parse 'to' and 'from' params:
	fromStr := query.Get("from")
	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return nil, trace.BadParameter("from")
		}
	}
	toStr := query.Get("to")
	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			return nil, trace.BadParameter("to")
		}
	}
	var limit int
	limitStr := query.Get("limit")
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil {
			return nil, trace.BadParameter("failed to parse limit: %q", limit)
		}
	}

	eventTypes := query[events.EventType]
	eventsList, _, err := auth.SearchEvents(from, to, apidefaults.Namespace, eventTypes, limit, types.EventOrderDescending, "")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return eventsList, nil
}

// searchSessionEvents only allows searching audit log for events related to session playback.
func (s *APIServer) searchSessionEvents(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var err error

	// default values for "to" and "from" fields
	to := time.Now().In(time.UTC) // now
	from := to.AddDate(0, -1, 0)  // one month ago

	// parse query for "to" and "from"
	query := r.URL.Query()
	fromStr := query.Get("from")
	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return nil, trace.BadParameter("from")
		}
	}
	toStr := query.Get("to")
	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			return nil, trace.BadParameter("to")
		}
	}
	var limit int
	limitStr := query.Get("limit")
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil {
			return nil, trace.BadParameter("failed to parse limit: %q", limit)
		}
	}
	// only pull back start and end events to build list of completed sessions
	eventsList, _, err := auth.SearchSessionEvents(from, to, limit, types.EventOrderDescending, "", nil, "")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return eventsList, nil
}

// HTTP GET /:version/sessions/:id/stream?offset=x&bytes=y
// Query parameters:
//
//	"offset"   : bytes from the beginning
//	"bytes"    : number of bytes to read (it won't return more than 512Kb)
func (s *APIServer) getSessionChunk(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	sid, err := session.ParseID(p.ByName("id"))
	if err != nil {
		return nil, trace.BadParameter("missing parameter id")
	}
	namespace := p.ByName("namespace")
	if !types.IsValidNamespace(namespace) {
		return nil, trace.BadParameter("invalid namespace %q", namespace)
	}

	// "offset bytes" query param
	offsetBytes, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offsetBytes < 0 {
		offsetBytes = 0
	}
	// "max bytes" query param
	max, err := strconv.Atoi(r.URL.Query().Get("bytes"))
	if err != nil || offsetBytes < 0 {
		offsetBytes = 0
	}
	log.Debugf("apiserver.GetSessionChunk(%v, %v, offset=%d)", namespace, *sid, offsetBytes)
	w.Header().Set("Content-Type", "text/plain")

	buffer, err := auth.GetSessionChunk(namespace, *sid, offsetBytes, max)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if _, err = w.Write(buffer); err != nil {
		return nil, trace.Wrap(err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	return nil, nil
}

// HTTP GET /:version/sessions/:id/events?maxage=n
// Query:
//
//	'after' : cursor value to return events newer than N. Defaults to 0, (return all)
func (s *APIServer) getSessionEvents(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	sid, err := session.ParseID(p.ByName("id"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	namespace := p.ByName("namespace")
	if !types.IsValidNamespace(namespace) {
		return nil, trace.BadParameter("invalid namespace %q", namespace)
	}
	afterN, err := strconv.Atoi(r.URL.Query().Get("after"))
	if err != nil {
		afterN = 0
	}
	includePrintEvents, err := strconv.ParseBool(r.URL.Query().Get("print"))
	if err != nil {
		includePrintEvents = false
	}

	return auth.GetSessionEvents(namespace, *sid, afterN, includePrintEvents)
}

type upsertNamespaceReq struct {
	Namespace types.Namespace `json:"namespace"`
}

func (s *APIServer) upsertNamespace(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req *upsertNamespaceReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.UpsertNamespace(req.Namespace); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

func (s *APIServer) getNamespaces(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	namespaces, err := auth.GetNamespaces()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return namespaces, nil
}

func (s *APIServer) getNamespace(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	name := p.ByName("namespace")
	if !types.IsValidNamespace(name) {
		return nil, trace.BadParameter("invalid namespace %q", name)
	}

	namespace, err := auth.GetNamespace(name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return namespace, nil
}

func (s *APIServer) deleteNamespace(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	name := p.ByName("namespace")
	if !types.IsValidNamespace(name) {
		return nil, trace.BadParameter("invalid namespace %q", name)
	}

	err := auth.DeleteNamespace(name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

func (s *APIServer) getClusterName(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	cn, err := auth.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return rawMessage(services.MarshalClusterName(cn, services.WithVersion(version), services.PreserveResourceID()))
}

type setClusterNameReq struct {
	ClusterName json.RawMessage `json:"cluster_name"`
}

func (s *APIServer) setClusterName(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req setClusterNameReq

	err := httplib.ReadJSON(r, &req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cn, err := services.UnmarshalClusterName(req.ClusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = auth.SetClusterName(cn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return message(fmt.Sprintf("cluster name set: %+v", cn)), nil
}

func (s *APIServer) getStaticTokens(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	st, err := auth.GetStaticTokens()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return rawMessage(services.MarshalStaticTokens(st, services.WithVersion(version), services.PreserveResourceID()))
}

func (s *APIServer) deleteStaticTokens(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteStaticTokens()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

type setStaticTokensReq struct {
	StaticTokens json.RawMessage `json:"static_tokens"`
}

func (s *APIServer) setStaticTokens(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req setStaticTokensReq

	err := httplib.ReadJSON(r, &req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	st, err := services.UnmarshalStaticTokens(req.StaticTokens)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = auth.SetStaticTokens(st)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return message(fmt.Sprintf("static tokens set: %+v", st)), nil
}

type upsertTunnelConnectionRawReq struct {
	TunnelConnection json.RawMessage `json:"tunnel_connection"`
}

// upsertTunnelConnection updates or inserts tunnel connection
func (s *APIServer) upsertTunnelConnection(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req upsertTunnelConnectionRawReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	conn, err := services.UnmarshalTunnelConnection(req.TunnelConnection)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.UpsertTunnelConnection(conn); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// getTunnelConnections returns a list of tunnel connections from a cluster
func (s *APIServer) getTunnelConnections(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	conns, err := auth.GetTunnelConnections(p.ByName("cluster"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]json.RawMessage, len(conns))
	for i, conn := range conns {
		data, err := services.MarshalTunnelConnection(conn, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		items[i] = data
	}
	return items, nil
}

// getAllTunnelConnections returns a list of tunnel connections from a cluster
func (s *APIServer) getAllTunnelConnections(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	conns, err := auth.GetAllTunnelConnections()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]json.RawMessage, len(conns))
	for i, conn := range conns {
		data, err := services.MarshalTunnelConnection(conn, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		items[i] = data
	}
	return items, nil
}

// deleteTunnelConnection deletes tunnel connection by name
func (s *APIServer) deleteTunnelConnection(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteTunnelConnection(p.ByName("cluster"), p.ByName("conn"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// deleteTunnelConnections deletes all tunnel connections for cluster
func (s *APIServer) deleteTunnelConnections(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteTunnelConnections(p.ByName("cluster"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// deleteAllTunnelConnections deletes all tunnel connections
func (s *APIServer) deleteAllTunnelConnections(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteAllTunnelConnections()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

type createRemoteClusterRawReq struct {
	// RemoteCluster is marshalled remote cluster resource
	RemoteCluster json.RawMessage `json:"remote_cluster"`
}

// createRemoteCluster creates remote cluster
func (s *APIServer) createRemoteCluster(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	var req createRemoteClusterRawReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	conn, err := services.UnmarshalRemoteCluster(req.RemoteCluster)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.CreateRemoteCluster(conn); err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// getRemoteClusters returns a list of remote clusters
func (s *APIServer) getRemoteClusters(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	clusters, err := auth.GetRemoteClusters()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]json.RawMessage, len(clusters))
	for i, cluster := range clusters {
		data, err := services.MarshalRemoteCluster(cluster, services.WithVersion(version), services.PreserveResourceID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		items[i] = data
	}
	return items, nil
}

// getRemoteCluster returns a remote cluster by name
func (s *APIServer) getRemoteCluster(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	cluster, err := auth.GetRemoteCluster(p.ByName("cluster"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rawMessage(services.MarshalRemoteCluster(cluster, services.WithVersion(version), services.PreserveResourceID()))
}

// deleteRemoteCluster deletes remote cluster by name
func (s *APIServer) deleteRemoteCluster(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteRemoteCluster(p.ByName("cluster"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

// deleteAllRemoteClusters deletes all remote clusters
func (s *APIServer) deleteAllRemoteClusters(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error) {
	err := auth.DeleteAllRemoteClusters()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return message("ok"), nil
}

func message(msg string) map[string]interface{} {
	return map[string]interface{}{"message": msg}
}
