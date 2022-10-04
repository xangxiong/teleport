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
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/session"
)

type upsertServerRawReq struct {
	Server json.RawMessage `json:"server"`
	TTL    time.Duration   `json:"ttl"`
}

type upsertReverseTunnelRawReq struct {
	ReverseTunnel json.RawMessage `json:"reverse_tunnel"`
	TTL           time.Duration   `json:"ttl"`
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

type upsertCertAuthorityRawReq struct {
	CA  json.RawMessage `json:"ca"`
	TTL time.Duration   `json:"ttl"`
}

type rotateExternalCertAuthorityRawReq struct {
	CA json.RawMessage `json:"ca"`
}

type createSessionReq struct {
	Session session.Session `json:"session"`
}

type updateSessionReq struct {
	Update session.UpdateRequest `json:"update"`
}

type upsertTunnelConnectionRawReq struct {
	TunnelConnection json.RawMessage `json:"tunnel_connection"`
}
