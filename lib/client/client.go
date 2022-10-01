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

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/client/webclient"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/observability/tracing"
	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/sshutils/scp"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/moby/term"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"
)

// ProxyClient implements ssh client to a teleport proxy
// It can provide list of nodes or connect to nodes
type ProxyClient struct {
	teleportClient *TeleportClient
	Client         *tracessh.Client
	Tracer         oteltrace.Tracer
	proxyAddress   string
	siteName       string
	clientAddr     string
}

// NodeClient implements ssh client to a ssh node (teleport or any regular ssh node)
// NodeClient can run shell and commands or upload and download files.
type NodeClient struct {
	Namespace string
	Tracer    oteltrace.Tracer
	Client    *tracessh.Client
	Proxy     *ProxyClient
	TC        *TeleportClient
	OnMFA     func()
}

// GetSites returns list of the "sites" (AKA teleport clusters) connected to the proxy
// Each site is returned as an instance of its auth server
func (proxy *ProxyClient) GetSites(ctx context.Context) ([]types.Site, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/GetSites",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", proxy.siteName),
		),
	)
	defer span.End()

	proxySession, err := proxy.Client.NewSession(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer proxySession.Close()
	stdout := &bytes.Buffer{}
	reader, err := proxySession.StdoutPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	done := make(chan struct{})
	go func() {
		if _, err := io.Copy(stdout, reader); err != nil {
			log.Warningf("Error reading STDOUT from proxy: %v", err)
		}
		close(done)
	}()
	// this function is async because,
	// the function call StdoutPipe() could fail if proxy rejected
	// the session request, and then RequestSubsystem call could hang
	// forever
	go func() {
		if err := proxySession.RequestSubsystem(ctx, "proxysites"); err != nil {
			log.Warningf("Failed to request subsystem: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(apidefaults.DefaultDialTimeout):
		return nil, trace.ConnectionProblem(nil, "timeout")
	}
	log.Debugf("Found clusters: %v", stdout.String())
	var sites []types.Site
	if err := json.Unmarshal(stdout.Bytes(), &sites); err != nil {
		return nil, trace.Wrap(err)
	}
	return sites, nil
}

// GetLeafClusters returns the leaf/remote clusters.
func (proxy *ProxyClient) GetLeafClusters(ctx context.Context) ([]types.RemoteCluster, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/GetLeafClusters",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", proxy.siteName),
		),
	)
	defer span.End()

	clt, err := proxy.ConnectToRootCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer clt.Close()

	remoteClusters, err := clt.GetRemoteClusters()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return remoteClusters, nil
}

// ReissueParams encodes optional parameters for
// user certificate reissue.
type ReissueParams struct {
	RouteToCluster        string
	NodeName              string
	KubernetesCluster     string
	AccessRequests        []string
	DropAccessRequests    []string
	RouteToDatabase       proto.RouteToDatabase
	RouteToApp            proto.RouteToApp
	RouteToWindowsDesktop proto.RouteToWindowsDesktop

	// ExistingCreds is a gross hack for lib/web/terminal.go to pass in
	// existing user credentials. The TeleportClient in lib/web/terminal.go
	// doesn't have a real LocalKeystore and keeps all certs in memory.
	// Normally, existing credentials are loaded from
	// TeleportClient.localAgent.
	//
	// TODO(awly): refactor lib/web to use a Keystore implementation that
	// mimics LocalKeystore and remove this.
	ExistingCreds *Key

	// MFACheck is optional parameter passed if MFA check was already done.
	// It can be nil.
	MFACheck *proto.IsMFARequiredResponse
}

// CertCachePolicy describes what should happen to the certificate cache when a
// user certificate is re-issued
type CertCachePolicy int

const (
	// CertCacheDrop indicates that all user certificates should be dropped as
	// part of the re-issue process. This can be necessary if the roles
	// assigned to the user are expected to change as a part of the re-issue.
	CertCacheDrop CertCachePolicy = 0

	// CertCacheKeep indicates that all user certificates (except those
	// explicitly updated by the re-issue) should be preserved across the
	// re-issue process.
	CertCacheKeep CertCachePolicy = 1
)

// PromptMFAChallengeHandler is a handler for MFA challenges.
//
// The challenge c from proxyAddr should be presented to the user, asking to
// use one of their registered MFA devices. User's response should be returned,
// or an error if anything goes wrong.
type PromptMFAChallengeHandler func(ctx context.Context, proxyAddr string, c *proto.MFAAuthenticateChallenge) (*proto.MFAAuthenticateResponse, error)

// RootClusterName returns name of the current cluster
func (proxy *ProxyClient) RootClusterName(ctx context.Context) (string, error) {
	_, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/RootClusterName",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	tlsKey, err := proxy.localAgent().GetCoreKey()
	if err != nil {
		if trace.IsNotFound(err) {
			// Fallback to TLS client certificates.
			tls := proxy.teleportClient.TLS
			if len(tls.Certificates) == 0 || len(tls.Certificates[0].Certificate) == 0 {
				return "", trace.BadParameter("missing TLS.Certificates")
			}
			cert, err := x509.ParseCertificate(tls.Certificates[0].Certificate[0])
			if err != nil {
				return "", trace.Wrap(err)
			}

			clusterName := cert.Issuer.CommonName
			if clusterName == "" {
				return "", trace.NotFound("failed to extract root cluster name from Teleport TLS cert")
			}
			return clusterName, nil
		}
		return "", trace.Wrap(err)
	}
	return tlsKey.RootClusterName()
}

// CreateAccessRequest registers a new access request with the auth server.
func (proxy *ProxyClient) CreateAccessRequest(ctx context.Context, req types.AccessRequest) error {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/CreateAccessRequest",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(attribute.String("request", req.GetName())),
	)
	defer span.End()

	site, err := proxy.ConnectToCurrentCluster(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	return site.CreateAccessRequest(ctx, req)
}

// GetAccessRequests loads all access requests matching the supplied filter.
func (proxy *ProxyClient) GetAccessRequests(ctx context.Context, filter types.AccessRequestFilter) ([]types.AccessRequest, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/GetAccessRequests",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("id", filter.ID),
			attribute.String("user", filter.User),
		),
	)
	defer span.End()

	site, err := proxy.ConnectToCurrentCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	reqs, err := site.GetAccessRequests(ctx, filter)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return reqs, nil
}

// GetRole loads a role resource by name.
func (proxy *ProxyClient) GetRole(ctx context.Context, name string) (types.Role, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/GetRole",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("role", name),
		),
	)
	defer span.End()

	site, err := proxy.ConnectToCurrentCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	role, err := site.GetRole(ctx, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return role, nil
}

// NewWatcher sets up a new event watcher.
func (proxy *ProxyClient) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/NewWatcher",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("name", watch.Name),
		),
	)
	defer span.End()

	site, err := proxy.ConnectToCurrentCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	watcher, err := site.NewWatcher(ctx, watch)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return watcher, nil
}

// isAuthBoring checks whether or not the auth server for the current cluster was compiled with BoringCrypto.
func (proxy *ProxyClient) isAuthBoring(ctx context.Context) (bool, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/isAuthBoring",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	site, err := proxy.ConnectToCurrentCluster(ctx)
	if err != nil {
		return false, trace.Wrap(err)
	}
	resp, err := site.Ping(ctx)
	return resp.IsBoring, trace.Wrap(err)
}

// FindNodesByFilters returns list of the nodes which have filters matched.
func (proxy *ProxyClient) FindNodesByFilters(ctx context.Context, req proto.ListResourcesRequest) ([]types.Server, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/FindNodesByFilters",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("resource", req.ResourceType),
			attribute.Int("limit", int(req.Limit)),
			attribute.String("predicate", req.PredicateExpression),
			attribute.StringSlice("keywords", req.SearchKeywords),
		),
	)
	defer span.End()

	cluster, err := proxy.currentCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	servers, err := proxy.FindNodesByFiltersForCluster(ctx, req, cluster.Name)
	return servers, trace.Wrap(err)
}

func (proxy *ProxyClient) GetClusterAlerts(ctx context.Context, req types.GetClusterAlertsRequest) ([]types.ClusterAlert, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/GetClusterAlerts",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	site, err := proxy.CurrentClusterAccessPoint(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer site.Close()

	alerts, err := site.GetClusterAlerts(ctx, req)
	return alerts, trace.Wrap(err)
}

// FindNodesByFiltersForCluster returns list of the nodes in a specified cluster which have filters matched.
func (proxy *ProxyClient) FindNodesByFiltersForCluster(ctx context.Context, req proto.ListResourcesRequest, cluster string) ([]types.Server, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/FindNodesByFiltersForCluster",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", cluster),
			attribute.String("resource", req.ResourceType),
			attribute.Int("limit", int(req.Limit)),
			attribute.String("predicate", req.PredicateExpression),
			attribute.StringSlice("keywords", req.SearchKeywords),
		),
	)
	defer span.End()

	req.ResourceType = types.KindNode

	site, err := proxy.ClusterAccessPoint(ctx, cluster)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resources, err := client.GetResourcesWithFilters(ctx, site, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	servers, err := types.ResourcesWithLabels(resources).AsServers()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return servers, nil
}

// ListResources returns a paginated list of resources.
func (proxy *ProxyClient) ListResources(ctx context.Context, namespace, resource, startKey string, limit int) ([]types.ResourceWithLabels, string, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/ListResources",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("resource", resource),
			attribute.Int("limit", limit),
		),
	)
	defer span.End()

	authClient, err := proxy.CurrentClusterAccessPoint(ctx)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	resp, err := authClient.ListResources(ctx, proto.ListResourcesRequest{
		Namespace:    namespace,
		ResourceType: resource,
		StartKey:     startKey,
		Limit:        int32(limit),
	})
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	return resp.Resources, resp.NextKey, nil
}

// CurrentClusterAccessPoint returns cluster access point to the currently
// selected cluster and is used for discovery
// and could be cached based on the access policy
func (proxy *ProxyClient) CurrentClusterAccessPoint(ctx context.Context) (auth.ClientI, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/CurrentClusterAccessPoint",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	// get the current cluster:
	cluster, err := proxy.currentCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return proxy.ClusterAccessPoint(ctx, cluster.Name)
}

// ClusterAccessPoint returns cluster access point used for discovery
// and could be cached based on the access policy
func (proxy *ProxyClient) ClusterAccessPoint(ctx context.Context, clusterName string) (auth.ClientI, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/ClusterAccessPoint",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", clusterName),
		),
	)
	defer span.End()

	if clusterName == "" {
		return nil, trace.BadParameter("parameter clusterName is missing")
	}
	clt, err := proxy.ConnectToCluster(ctx, clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return clt, nil
}

// ConnectToCurrentCluster connects to the auth server of the currently selected
// cluster via proxy. It returns connected and authenticated auth server client
//
// if 'quiet' is set to true, no errors will be printed to stdout, otherwise
// any connection errors are visible to a user.
func (proxy *ProxyClient) ConnectToCurrentCluster(ctx context.Context) (auth.ClientI, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/ConnectToCurrentCluster",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	cluster, err := proxy.currentCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return proxy.ConnectToCluster(ctx, cluster.Name)
}

// ConnectToRootCluster connects to the auth server of the root cluster
// via proxy. It returns connected and authenticated auth server client
//
// if 'quiet' is set to true, no errors will be printed to stdout, otherwise
// any connection errors are visible to a user.
func (proxy *ProxyClient) ConnectToRootCluster(ctx context.Context) (auth.ClientI, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/ConnectToRootCluster",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	clusterName, err := proxy.RootClusterName(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return proxy.ConnectToCluster(ctx, clusterName)
}

func (proxy *ProxyClient) loadTLS(clusterName string) (*tls.Config, error) {
	if proxy.teleportClient.SkipLocalAuth {
		return proxy.teleportClient.TLS.Clone(), nil
	}
	tlsKey, err := proxy.localAgent().GetCoreKey()
	if err != nil {
		return nil, trace.Wrap(err, "failed to fetch TLS key for %v", proxy.teleportClient.Username)
	}

	tlsConfig, err := tlsKey.TeleportClientTLSConfig(nil, []string{clusterName})
	if err != nil {
		return nil, trace.Wrap(err, "failed to generate client TLS config")
	}
	return tlsConfig.Clone(), nil
}

// ConnectToAuthServiceThroughALPNSNIProxy uses ALPN proxy service to connect to remote/local auth
// service and returns auth client. For routing purposes, TLS ServerName is set to destination auth service
// cluster name with ALPN values set to teleport-auth protocol.
func (proxy *ProxyClient) ConnectToAuthServiceThroughALPNSNIProxy(ctx context.Context, clusterName, proxyAddr string) (auth.ClientI, error) {
	tlsConfig, err := proxy.loadTLS(clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if proxyAddr == "" {
		proxyAddr = proxy.teleportClient.WebProxyAddr
	}

	tlsConfig.InsecureSkipVerify = proxy.teleportClient.InsecureSkipVerify
	clt, err := auth.NewClient(client.Config{
		Context: ctx,
		Addrs:   []string{proxyAddr},
		Credentials: []client.Credentials{
			client.LoadTLS(tlsConfig),
		},
		ALPNSNIAuthDialClusterName: clusterName,
		CircuitBreakerConfig:       breaker.NoopBreakerConfig(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return clt, nil
}

func (proxy *ProxyClient) shouldDialWithTLSRouting(ctx context.Context) (string, bool) {
	if len(proxy.teleportClient.JumpHosts) > 0 {
		// Check if the provided JumpHost address is a Teleport Proxy.
		// This is needed to distinguish if the JumpHost address from Teleport Proxy Web address
		// or Teleport Proxy SSH address.
		jumpHostAddr := proxy.teleportClient.JumpHosts[0].Addr.String()
		resp, err := webclient.Find(
			&webclient.Config{
				Context:   ctx,
				ProxyAddr: jumpHostAddr,
				Insecure:  proxy.teleportClient.InsecureSkipVerify,
			},
		)
		if err != nil {
			// HTTP ping call failed. The JumpHost address is not a Teleport proxy address
			return "", false
		}
		return jumpHostAddr, resp.Proxy.TLSRoutingEnabled
	}
	return proxy.teleportClient.WebProxyAddr, proxy.teleportClient.TLSRoutingEnabled
}

// ConnectToCluster connects to the auth server of the given cluster via proxy.
// It returns connected and authenticated auth server client
func (proxy *ProxyClient) ConnectToCluster(ctx context.Context, clusterName string) (auth.ClientI, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/ConnectToCluster",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", clusterName),
		),
	)
	defer span.End()

	if proxyAddr, ok := proxy.shouldDialWithTLSRouting(ctx); ok {
		// If proxy supports multiplex listener mode dial root/leaf cluster auth service via ALPN Proxy
		// directly without using SSH tunnels.
		clt, err := proxy.ConnectToAuthServiceThroughALPNSNIProxy(ctx, clusterName, proxyAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return clt, nil
	}

	dialer := client.ContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		// link the span created dialing the auth server to the one created above. grpc dialing
		// passes in a context.Background() during dial which causes these two spans to be in
		// different traces.
		ctx = oteltrace.ContextWithSpan(ctx, span)
		return proxy.dialAuthServer(ctx, clusterName)
	})

	if proxy.teleportClient.SkipLocalAuth {
		return auth.NewClient(client.Config{
			Context: ctx,
			Dialer:  dialer,
			Credentials: []client.Credentials{
				client.LoadTLS(proxy.teleportClient.TLS),
			},
			CircuitBreakerConfig: breaker.NoopBreakerConfig(),
		})
	}

	tlsKey, err := proxy.localAgent().GetCoreKey()
	if err != nil {
		return nil, trace.Wrap(err, "failed to fetch TLS key for %v", proxy.teleportClient.Username)
	}
	tlsConfig, err := tlsKey.TeleportClientTLSConfig(nil, []string{clusterName})
	if err != nil {
		return nil, trace.Wrap(err, "failed to generate client TLS config")
	}
	tlsConfig.InsecureSkipVerify = proxy.teleportClient.InsecureSkipVerify
	clt, err := auth.NewClient(client.Config{
		Context: ctx,
		Dialer:  dialer,
		Credentials: []client.Credentials{
			client.LoadTLS(tlsConfig),
		},
		CircuitBreakerConfig: breaker.NoopBreakerConfig(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return clt, nil
}

// NewTracingClient connects to the auth server of the given cluster via proxy.
// It returns a connected and authenticated tracing.Client that will export spans
// to the auth server, where they will be forwarded onto the configured exporter.
func (proxy *ProxyClient) NewTracingClient(ctx context.Context, clusterName string) (*tracing.Client, error) {
	dialer := client.ContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return proxy.dialAuthServer(ctx, clusterName)
	})

	switch {
	case proxy.teleportClient.TLSRoutingEnabled:
		tlsConfig, err := proxy.loadTLS(clusterName)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		clt, err := client.NewTracingClient(ctx, client.Config{
			Addrs:            []string{proxy.teleportClient.WebProxyAddr},
			DialInBackground: true,
			Credentials: []client.Credentials{
				client.LoadTLS(tlsConfig),
			},
			ALPNSNIAuthDialClusterName: clusterName,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return clt, nil
	case proxy.teleportClient.SkipLocalAuth:
		clt, err := client.NewTracingClient(ctx, client.Config{
			Dialer:           dialer,
			DialInBackground: true,
			Credentials: []client.Credentials{
				client.LoadTLS(proxy.teleportClient.TLS),
			},
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return clt, nil
	default:
		tlsKey, err := proxy.localAgent().GetCoreKey()
		if err != nil {
			return nil, trace.Wrap(err, "failed to fetch TLS key for %v", proxy.teleportClient.Username)
		}

		tlsConfig, err := tlsKey.TeleportClientTLSConfig(nil, []string{clusterName})
		if err != nil {
			return nil, trace.Wrap(err, "failed to generate client TLS config")
		}
		tlsConfig.InsecureSkipVerify = proxy.teleportClient.InsecureSkipVerify

		clt, err := client.NewTracingClient(ctx, client.Config{
			Dialer:           dialer,
			DialInBackground: true,
			Credentials: []client.Credentials{
				client.LoadTLS(tlsConfig),
			},
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return clt, nil
	}
}

// nodeName removes the port number from the hostname, if present
func nodeName(node string) string {
	n, _, err := net.SplitHostPort(node)
	if err != nil {
		return node
	}
	return n
}

// dialAuthServer returns auth server connection forwarded via proxy
func (proxy *ProxyClient) dialAuthServer(ctx context.Context, clusterName string) (net.Conn, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/dialAuthServer",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			attribute.String("cluster", clusterName),
		),
	)
	defer span.End()

	log.Debugf("Client %v is connecting to auth server on cluster %q.", proxy.clientAddr, clusterName)

	address := "@" + clusterName

	// parse destination first:
	localAddr, err := utils.ParseAddr("tcp://" + proxy.proxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fakeAddr, err := utils.ParseAddr("tcp://" + address)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	proxySession, err := proxy.Client.NewSession(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	proxyWriter, err := proxySession.StdinPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	proxyReader, err := proxySession.StdoutPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	proxyErr, err := proxySession.StderrPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = proxySession.RequestSubsystem(ctx, "proxy:"+address)
	if err != nil {
		// read the stderr output from the failed SSH session and append
		// it to the end of our own message:
		serverErrorMsg, _ := io.ReadAll(proxyErr)
		return nil, trace.ConnectionProblem(err, "failed connecting to node %v. %s",
			nodeName(strings.Split(address, "@")[0]), serverErrorMsg)
	}
	return utils.NewPipeNetConn(
		proxyReader,
		proxyWriter,
		proxySession,
		localAddr,
		fakeAddr,
	), nil
}

// NodeDetails provides connection information for a node
type NodeDetails struct {
	// Addr is an address to dial
	Addr string
	// Namespace is the node namespace
	Namespace string
	// Cluster is the name of the target cluster
	Cluster string

	// MFACheck is optional parameter passed if MFA check was already done.
	// It can be nil.
	MFACheck *proto.IsMFARequiredResponse
}

// String returns a user-friendly name
func (n NodeDetails) String() string {
	parts := []string{nodeName(n.Addr)}
	if n.Cluster != "" {
		parts = append(parts, "on cluster", n.Cluster)
	}
	return strings.Join(parts, " ")
}

// ProxyFormat returns the address in the format
// used by the proxy subsystem
func (n *NodeDetails) ProxyFormat() string {
	parts := []string{n.Addr}
	if n.Namespace != "" {
		parts = append(parts, n.Namespace)
	}
	if n.Cluster != "" {
		parts = append(parts, n.Cluster)
	}
	return strings.Join(parts, "@")
}

func (proxy *ProxyClient) Close() error {
	return proxy.Client.Close()
}

// ExecuteSCP runs remote scp command(shellCmd) on the remote server and
// runs local scp handler using SCP Command
func (c *NodeClient) ExecuteSCP(ctx context.Context, cmd scp.Command) error {
	ctx, span := c.Tracer.Start(
		ctx,
		"nodeClient/ExecuteSCP",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	shellCmd, err := cmd.GetRemoteShellCmd()
	if err != nil {
		return trace.Wrap(err)
	}

	s, err := c.Client.NewSession(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer s.Close()

	stdin, err := s.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	stdout, err := s.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	// Stream scp's stderr so tsh gets the verbose remote error
	// if the command fails
	stderr, err := s.StderrPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	go io.Copy(os.Stderr, stderr)

	ch := utils.NewPipeNetConn(
		stdout,
		stdin,
		utils.MultiCloser(),
		&net.IPAddr{},
		&net.IPAddr{},
	)

	execC := make(chan error, 1)
	go func() {
		err := cmd.Execute(ch)
		if err != nil && !trace.IsEOF(err) {
			log.WithError(err).Warn("Failed to execute SCP command.")
		}
		stdin.Close()
		execC <- err
	}()

	runC := make(chan error, 1)
	go func() {
		err := s.Run(ctx, shellCmd)
		if err != nil && errors.Is(err, &ssh.ExitMissingError{}) {
			// TODO(dmitri): currently, if the session is aborted with (*session).Close,
			// the remote side cannot send exit-status and this error results.
			// To abort the session properly, Teleport needs to support `signal` request
			err = nil
		}
		runC <- err
	}()

	var runErr error
	select {
	case <-ctx.Done():
		if err := s.Close(); err != nil {
			log.WithError(err).Debug("Failed to close the SSH session.")
		}
		err, runErr = <-execC, <-runC
	case err = <-execC:
		runErr = <-runC
	case runErr = <-runC:
		err = <-execC
	}

	if runErr != nil && (err == nil || trace.IsEOF(err)) {
		err = runErr
	}
	if trace.IsEOF(err) {
		err = nil
	}
	return trace.Wrap(err)
}

// GetRemoteTerminalSize fetches the terminal size of a given SSH session.
func (c *NodeClient) GetRemoteTerminalSize(ctx context.Context, sessionID string) (*term.Winsize, error) {
	ctx, span := c.Tracer.Start(
		ctx,
		"nodeClient/GetRemoteTerminalSize",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(attribute.String("session", sessionID)),
	)
	defer span.End()

	ok, payload, err := c.Client.SendRequest(ctx, teleport.TerminalSizeRequest, true, []byte(sessionID))
	if err != nil {
		return nil, trace.Wrap(err)
	} else if !ok {
		return nil, trace.BadParameter("failed to get terminal size")
	}

	ws := new(term.Winsize)
	err = json.Unmarshal(payload, ws)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ws, nil
}

// Close closes client and it's operations
func (c *NodeClient) Close() error {
	return c.Client.Close()
}

// currentCluster returns the connection to the API of the current cluster
func (proxy *ProxyClient) currentCluster(ctx context.Context) (*types.Site, error) {
	ctx, span := proxy.Tracer.Start(
		ctx,
		"proxyClient/currentCluster",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)
	defer span.End()

	sites, err := proxy.GetSites(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(sites) == 0 {
		return nil, trace.NotFound("no clusters registered")
	}
	if proxy.siteName == "" {
		return &sites[0], nil
	}
	for _, site := range sites {
		if site.Name == proxy.siteName {
			return &site, nil
		}
	}
	return nil, trace.NotFound("cluster %v not found", proxy.siteName)
}

// localAgent returns for the Teleport client's local agent.
func (proxy *ProxyClient) localAgent() *LocalKeyAgent {
	return proxy.teleportClient.LocalAgent()
}

// GetPaginatedSessions grabs up to 'max' sessions.
func GetPaginatedSessions(ctx context.Context, fromUTC, toUTC time.Time, pageSize int, order types.EventOrder, max int, authClient auth.ClientI) ([]apievents.AuditEvent, error) {
	prevEventKey := ""
	var sessions []apievents.AuditEvent
	for {
		if remaining := max - len(sessions); remaining < pageSize {
			pageSize = remaining
		}
		nextEvents, eventKey, err := authClient.SearchSessionEvents(fromUTC, toUTC,
			pageSize, order, prevEventKey, nil /* where condition */, "" /* session ID */)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		sessions = append(sessions, nextEvents...)
		if eventKey == "" || len(sessions) >= max {
			break
		}
		prevEventKey = eventKey
	}
	if max < len(sessions) {
		return sessions[:max], nil
	}
	return sessions, nil
}
