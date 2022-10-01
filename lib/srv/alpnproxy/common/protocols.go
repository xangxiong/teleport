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

package common

import (
	"strings"
)

// Protocol is the TLS ALPN protocol type.
type Protocol string

const (
	// ProtocolProxySSH is TLS ALPN protocol value used to indicate Proxy SSH protocol.
	ProtocolProxySSH Protocol = "teleport-proxy-ssh"

	// ProtocolReverseTunnel is TLS ALPN protocol value used to indicate Proxy reversetunnel protocol.
	ProtocolReverseTunnel Protocol = "teleport-reversetunnel"

	// ProtocolReverseTunnelV2 is TLS ALPN protocol value used to indicate reversetunnel clients
	// that are aware of proxy peering. This is only used on the client side to allow intermediate
	// load balancers to make decisions based on the ALPN header. ProtocolReverseTunnel should still
	// be included in the list of ALPN header for the proxy server to handle the connection properly.
	ProtocolReverseTunnelV2 Protocol = "teleport-reversetunnelv2"

	// ProtocolHTTP is TLS ALPN protocol value used to indicate HTTP2 protocol
	// ProtocolHTTP is TLS ALPN protocol value used to indicate HTTP 1.1 protocol
	ProtocolHTTP Protocol = "http/1.1"

	// ProtocolHTTP2 is TLS ALPN protocol value used to indicate HTTP2 protocol.
	ProtocolHTTP2 Protocol = "h2"

	// ProtocolDefault is default TLS ALPN value.
	ProtocolDefault Protocol = ""

	// ProtocolAuth allows dialing local/remote auth service based on SNI cluster name value.
	ProtocolAuth Protocol = "teleport-auth@"

	// ProtocolProxyGRPC is TLS ALPN protocol value used to indicate gRPC
	// traffic intended for the Teleport proxy.
	ProtocolProxyGRPC Protocol = "teleport-proxy-grpc"

	// ProtocolTCP is TLS ALPN protocol value used to indicate plain TCP connection.
	ProtocolTCP Protocol = "teleport-tcp"

	// ProtocolPingSuffix is TLS ALPN suffix used to wrap connections with
	// Ping.
	ProtocolPingSuffix Protocol = "-ping"
)

// SupportedProtocols is the list of supported ALPN protocols.
var SupportedProtocols = []Protocol{
	ProtocolHTTP2,
	ProtocolHTTP,
	ProtocolProxySSH,
	ProtocolReverseTunnel,
	ProtocolAuth,
	ProtocolTCP,
}

// ProtocolsToString converts the list of Protocols to the list of strings.
func ProtocolsToString(protocols []Protocol) []string {
	out := make([]string, 0, len(protocols))
	for _, v := range protocols {
		out = append(out, string(v))
	}
	return out
}

// ProtocolsWithPing receives a list a protocols and returns a list of them with
// the Ping protocol suffix.
func ProtocolsWithPing(protocols ...Protocol) []Protocol {
	res := make([]Protocol, len(protocols))
	for i := range res {
		res[i] = ProtocolWithPing(protocols[i])
	}

	return res
}

// ProtocolWithPing receives a protocol and returns it with the Ping protocol
// suffix.
func ProtocolWithPing(protocol Protocol) Protocol {
	return Protocol(string(protocol) + string(ProtocolPingSuffix))
}

// IsPingProcotol checks if the provided protocol is suffixed with Ping.
func IsPingProtocol(protocol Protocol) bool {
	return strings.HasSuffix(string(protocol), string(ProtocolPingSuffix))
}
