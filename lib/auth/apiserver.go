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
	"net/http"
	"time"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/plugin"
	"github.com/gravitational/teleport/lib/session"

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

// HandlerWithAuthFunc is http handler with passed auth context
type HandlerWithAuthFunc func(auth ClientI, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (interface{}, error)

type upsertServerRawReq struct {
	Server json.RawMessage `json:"server"`
	TTL    time.Duration   `json:"ttl"`
}

type upsertReverseTunnelRawReq struct {
	ReverseTunnel json.RawMessage `json:"reverse_tunnel"`
	TTL           time.Duration   `json:"ttl"`
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

type generateHostCertReq struct {
	Key         []byte            `json:"key"`
	HostID      string            `json:"hostname"`
	NodeName    string            `json:"node_name"`
	Principals  []string          `json:"principals"`
	ClusterName string            `json:"auth_domain"`
	Roles       types.SystemRoles `json:"roles"`
	TTL         time.Duration     `json:"ttl"`
}

type registerNewAuthServerReq struct {
	Token string `json:"token"`
}

type upsertCertAuthorityRawReq struct {
	CA  json.RawMessage `json:"ca"`
	TTL time.Duration   `json:"ttl"`
}

type rotateExternalCertAuthorityRawReq struct {
	CA json.RawMessage `json:"ca"`
}

// deprecatedLocalCAResponse contains the concatenated PEM-encoded TLS certs for
// the local cluster's Host CA
// DELETE IN 11.0.0
type deprecatedLocalCAResponse struct {
	// TLSCA is a PEM-encoded TLS certificate authority.
	TLSCA []byte `json:"tls_ca"`
}

type createSessionReq struct {
	Session session.Session `json:"session"`
}

type updateSessionReq struct {
	Update session.UpdateRequest `json:"update"`
}

type upsertNamespaceReq struct {
	Namespace types.Namespace `json:"namespace"`
}

type upsertTunnelConnectionRawReq struct {
	TunnelConnection json.RawMessage `json:"tunnel_connection"`
}
