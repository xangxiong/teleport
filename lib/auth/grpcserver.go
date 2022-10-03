/*
Copyright 2018-2021 Gravitational, Inc.

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
	"io"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip" // gzip compressor for gRPC.
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/metadata"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/joinserver"
	"github.com/gravitational/teleport/lib/session"
)

// GRPCServer is GPRC Auth Server API
type GRPCServer struct {
	*logrus.Entry
	APIConfig
	server *grpc.Server

	// TraceServiceServer exposes the exporter server so that the auth server may
	// collect and forward spans
	collectortracepb.TraceServiceServer
}

// Export forwards OTLP traces to the upstream collector configured in the tracing service. This allows for
// tsh, tctl, etc to be able to export traces without having to know how to connect to the upstream collector
// for the cluster.
func (g *GRPCServer) Export(ctx context.Context, req *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(req.ResourceSpans) == 0 {
		return &collectortracepb.ExportTraceServiceResponse{}, nil
	}

	return auth.Export(ctx, req)
}

// GetServer returns an instance of grpc server
func (g *GRPCServer) GetServer() (*grpc.Server, error) {
	if g.server == nil {
		return nil, trace.BadParameter("grpc server has not been initialized")
	}

	return g.server, nil
}

// EmitAuditEvent emits audit event
func (g *GRPCServer) EmitAuditEvent(ctx context.Context, req *apievents.OneOf) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	event, err := apievents.FromOneOf(*req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = auth.EmitAuditEvent(ctx, event)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// SendKeepAlives allows node to send a stream of keep alive requests
func (g *GRPCServer) SendKeepAlives(stream proto.AuthService_SendKeepAlivesServer) error {
	defer stream.SendAndClose(&empty.Empty{})
	firstIteration := true
	for {
		// Authenticate within the loop to block locked-out nodes from heartbeating.
		auth, err := g.authenticate(stream.Context())
		if err != nil {
			return trace.Wrap(err)
		}
		keepAlive, err := stream.Recv()
		if err == io.EOF {
			g.Debugf("Connection closed.")
			return nil
		}
		if err != nil {
			g.Debugf("Failed to receive heartbeat: %v", err)
			return trace.Wrap(err)
		}
		err = auth.KeepAliveServer(stream.Context(), *keepAlive)
		if err != nil {
			return trace.Wrap(err)
		}
		if firstIteration {
			g.Debugf("Got heartbeat connection from %v.", auth.User.GetName())
			firstIteration = false
		}
	}
}

// logInterval is used to log stats after this many events
const logInterval = 10000

// WatchEvents returns a new stream of cluster events
func (g *GRPCServer) WatchEvents(watch *proto.Watch, stream proto.AuthService_WatchEventsServer) error {
	auth, err := g.authenticate(stream.Context())
	if err != nil {
		return trace.Wrap(err)
	}
	servicesWatch := types.Watch{
		Name: auth.User.GetName(),
	}
	for _, kind := range watch.Kinds {
		servicesWatch.Kinds = append(servicesWatch.Kinds, proto.ToWatchKind(kind))
	}

	if clusterName, err := auth.GetClusterName(); err == nil {
		// we might want to enforce a filter for older clients in certain conditions
		maybeFilterCertAuthorityWatches(stream.Context(), clusterName.GetClusterName(), auth.Checker.RoleNames(), &servicesWatch)
	}

	watcher, err := auth.NewWatcher(stream.Context(), servicesWatch)
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Close()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-watcher.Done():
			return watcher.Error()
		case event := <-watcher.Events():
			out, err := client.EventToGRPC(event)
			if err != nil {
				return trace.Wrap(err)
			}

			if err := stream.Send(out); err != nil {
				return trace.Wrap(err)
			}
		}
	}
}

// maybeFilterCertAuthorityWatches will add filters to the CertAuthority
// WatchKinds in the watch if the client is authenticated as just a `Node` with
// no other roles and if the client is older than the cutoff version, and if the
// WatchKind for KindCertAuthority is trivial, i.e. it's a WatchKind{Kind:
// KindCertAuthority} with no other fields set. In any other case we will assume
// that the client knows what it's doing and the cache watcher will still send
// everything.
//
// DELETE IN 10.0, no supported clients should require this at that point
func maybeFilterCertAuthorityWatches(ctx context.Context, clusterName string, roleNames []string, watch *types.Watch) {
	if len(roleNames) != 1 || roleNames[0] != string(types.RoleNode) {
		return
	}

	clientVersionString, ok := metadata.ClientVersionFromContext(ctx)
	if !ok {
		log.Debug("no client version found in grpc context")
		return
	}

	clientVersion, err := semver.NewVersion(clientVersionString)
	if err != nil {
		log.WithError(err).Debugf("couldn't parse client version %q", clientVersionString)
		return
	}

	// we treat the entire previous major version as "old" for this version
	// check, even if there might have been backports; compliant clients will
	// supply their own filter anyway
	if !clientVersion.LessThan(certAuthorityFilterVersionCutoff) {
		return
	}

	for i, k := range watch.Kinds {
		if k.Kind != types.KindCertAuthority || !k.IsTrivial() {
			continue
		}

		log.Debugf("Injecting filter for CertAuthority watch for Node-only watcher with version %v", clientVersion)
		watch.Kinds[i].Filter = types.CertAuthorityFilter{
			types.HostCA: clusterName,
			types.UserCA: types.Wildcard,
		}.IntoMap()
	}
}

// certAuthorityFilterVersionCutoff is the version starting from which we stop
// injecting filters for CertAuthority watches in maybeFilterCertAuthorityWatches.
var certAuthorityFilterVersionCutoff = *semver.New("9.0.0")

func (g *GRPCServer) GenerateHostCerts(ctx context.Context, req *proto.HostCertsRequest) (*proto.Certs, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Pass along the remote address the request came from to the registration function.
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, trace.BadParameter("unable to find peer")
	}
	req.RemoteAddr = p.Addr.String()

	certs, err := auth.ServerWithRoles.GenerateHostCerts(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return certs, nil
}

// DELETE IN: 12.0 (deprecated in v11, but required for back-compat with v10 clients)
func (g *GRPCServer) UnstableAssertSystemRole(ctx context.Context, req *proto.UnstableSystemRoleAssertion) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}

	if err := auth.UnstableAssertSystemRole(ctx, *req); err != nil {
		return nil, trail.ToGRPC(err)
	}

	return &empty.Empty{}, nil
}

func (g *GRPCServer) InventoryControlStream(stream proto.AuthService_InventoryControlStreamServer) error {
	auth, err := g.authenticate(stream.Context())
	if err != nil {
		return trail.ToGRPC(err)
	}

	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return trace.BadParameter("unable to find peer")
	}

	ics := client.NewUpstreamInventoryControlStream(stream, p.Addr.String())

	if err := auth.RegisterInventoryControlStream(ics); err != nil {
		return trail.ToGRPC(err)
	}

	// hold open the stream until it completes
	<-ics.Done()

	if trace.IsEOF(ics.Error()) {
		return nil
	}

	return trail.ToGRPC(ics.Error())
}

func (g *GRPCServer) GetInventoryStatus(ctx context.Context, req *proto.InventoryStatusRequest) (*proto.InventoryStatusSummary, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}

	rsp, err := auth.GetInventoryStatus(ctx, *req)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}

	return &rsp, nil
}

func (g *GRPCServer) PingInventory(ctx context.Context, req *proto.InventoryPingRequest) (*proto.InventoryPingResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}

	rsp, err := auth.PingInventory(ctx, *req)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}

	return &rsp, nil
}

func (g *GRPCServer) GetCurrentUser(ctx context.Context, req *empty.Empty) (*types.UserV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := auth.ServerWithRoles.GetCurrentUser(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	v2, ok := user.(*types.UserV2)
	if !ok {
		log.Warnf("expected type services.UserV2, got %T for user %q", user, user.GetName())
		return nil, trace.Errorf("encountered unexpected user type")
	}
	return v2, nil
}

func (g *GRPCServer) GetCurrentUserRoles(_ *empty.Empty, stream proto.AuthService_GetCurrentUserRolesServer) error {
	auth, err := g.authenticate(stream.Context())
	if err != nil {
		return trace.Wrap(err)
	}
	roles, err := auth.ServerWithRoles.GetCurrentUserRoles(stream.Context())
	if err != nil {
		return trace.Wrap(err)
	}
	for _, role := range roles {
		v5, ok := role.(*types.RoleV5)
		if !ok {
			log.Warnf("expected type RoleV5, got %T for role %q", role, role.GetName())
			return trace.Errorf("encountered unexpected role type")
		}
		if err := stream.Send(v5); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// DEPRECATED, DELETE IN 11.0.0: Use GetAccessRequestsV2 instead.
func (g *GRPCServer) GetAccessRequests(ctx context.Context, f *types.AccessRequestFilter) (*proto.AccessRequests, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var filter types.AccessRequestFilter
	if f != nil {
		filter = *f
	}
	reqs, err := auth.ServerWithRoles.GetAccessRequests(ctx, filter)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	collector := make([]*types.AccessRequestV3, 0, len(reqs))
	for _, req := range reqs {
		r, ok := req.(*types.AccessRequestV3)
		if !ok {
			err = trace.BadParameter("unexpected access request type %T", req)
			return nil, trace.Wrap(err)
		}
		collector = append(collector, r)
	}
	return &proto.AccessRequests{
		AccessRequests: collector,
	}, nil
}

func (g *GRPCServer) GetAccessRequestsV2(f *types.AccessRequestFilter, stream proto.AuthService_GetAccessRequestsV2Server) error {
	ctx := stream.Context()
	auth, err := g.authenticate(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	var filter types.AccessRequestFilter
	if f != nil {
		filter = *f
	}
	reqs, err := auth.ServerWithRoles.GetAccessRequests(ctx, filter)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, req := range reqs {
		r, ok := req.(*types.AccessRequestV3)
		if !ok {
			err = trace.BadParameter("unexpected access request type %T", req)
			return trace.Wrap(err)
		}

		if err := stream.Send(r); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (g *GRPCServer) SetAccessRequestState(ctx context.Context, req *proto.RequestStateSetter) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if req.Delegator != "" {
		ctx = WithDelegator(ctx, req.Delegator)
	}
	if err := auth.ServerWithRoles.SetAccessRequestState(ctx, types.AccessRequestUpdate{
		RequestID:   req.ID,
		State:       req.State,
		Reason:      req.Reason,
		Annotations: req.Annotations,
		Roles:       req.Roles,
	}); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// GetPluginData loads all plugin data matching the supplied filter.
func (g *GRPCServer) GetPluginData(ctx context.Context, filter *types.PluginDataFilter) (*proto.PluginDataSeq, error) {
	// TODO(fspmarshall): Implement rate-limiting to prevent misbehaving plugins from
	// consuming too many server resources.
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	data, err := auth.ServerWithRoles.GetPluginData(ctx, *filter)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var seq []*types.PluginDataV3
	for _, rsc := range data {
		d, ok := rsc.(*types.PluginDataV3)
		if !ok {
			err = trace.BadParameter("unexpected plugin data type %T", rsc)
			return nil, trace.Wrap(err)
		}
		seq = append(seq, d)
	}
	return &proto.PluginDataSeq{
		PluginData: seq,
	}, nil
}

func (g *GRPCServer) Ping(ctx context.Context, req *proto.PingRequest) (*proto.PingResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rsp, err := auth.Ping(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// attempt to set remote addr.
	if p, ok := peer.FromContext(ctx); ok {
		rsp.RemoteAddr = p.Addr.String()
	}

	return &rsp, nil
}

// AcquireSemaphore acquires lease with requested resources from semaphore.
func (g *GRPCServer) AcquireSemaphore(ctx context.Context, params *types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	lease, err := auth.AcquireSemaphore(ctx, *params)
	return lease, trace.Wrap(err)
}

// KeepAliveSemaphoreLease updates semaphore lease.
func (g *GRPCServer) KeepAliveSemaphoreLease(ctx context.Context, req *types.SemaphoreLease) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.KeepAliveSemaphoreLease(ctx, *req); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// CancelSemaphoreLease cancels semaphore lease early.
func (g *GRPCServer) CancelSemaphoreLease(ctx context.Context, req *types.SemaphoreLease) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := auth.CancelSemaphoreLease(ctx, *req); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// GetSemaphores returns a list of all semaphores matching the supplied filter.
func (g *GRPCServer) GetSemaphores(ctx context.Context, req *types.SemaphoreFilter) (*proto.Semaphores, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	semaphores, err := auth.GetSemaphores(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ss := make([]*types.SemaphoreV3, 0, len(semaphores))
	for _, sem := range semaphores {
		s, ok := sem.(*types.SemaphoreV3)
		if !ok {
			return nil, trace.BadParameter("unexpected semaphore type: %T", sem)
		}
		ss = append(ss, s)
	}
	return &proto.Semaphores{
		Semaphores: ss,
	}, nil
}

// GetTrustedCluster retrieves a Trusted Cluster by name.
func (g *GRPCServer) GetTrustedCluster(ctx context.Context, req *types.ResourceRequest) (*types.TrustedClusterV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tc, err := auth.ServerWithRoles.GetTrustedCluster(ctx, req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	trustedClusterV2, ok := tc.(*types.TrustedClusterV2)
	if !ok {
		return nil, trace.Errorf("encountered unexpected Trusted Cluster type %T", tc)
	}
	return trustedClusterV2, nil
}

// GetTrustedClusters retrieves all Trusted Clusters.
func (g *GRPCServer) GetTrustedClusters(ctx context.Context, _ *empty.Empty) (*types.TrustedClusterV2List, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tcs, err := auth.ServerWithRoles.GetTrustedClusters(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	trustedClustersV2 := make([]*types.TrustedClusterV2, len(tcs))
	for i, tc := range tcs {
		var ok bool
		if trustedClustersV2[i], ok = tc.(*types.TrustedClusterV2); !ok {
			return nil, trace.Errorf("encountered unexpected Trusted Cluster type: %T", tc)
		}
	}
	return &types.TrustedClusterV2List{
		TrustedClusters: trustedClustersV2,
	}, nil
}

// GenerateToken generates a new auth token.
func (g *GRPCServer) GenerateToken(ctx context.Context, req *proto.GenerateTokenRequest) (*proto.GenerateTokenResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := auth.ServerWithRoles.GenerateToken(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &proto.GenerateTokenResponse{Token: token}, nil
}

// GetClusterAuditConfig gets cluster audit configuration.
func (g *GRPCServer) GetClusterAuditConfig(ctx context.Context, _ *empty.Empty) (*types.ClusterAuditConfigV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	auditConfig, err := auth.ServerWithRoles.GetClusterAuditConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	auditConfigV2, ok := auditConfig.(*types.ClusterAuditConfigV2)
	if !ok {
		return nil, trace.BadParameter("unexpected type %T", auditConfig)
	}
	return auditConfigV2, nil
}

// GetClusterNetworkingConfig gets cluster networking configuration.
func (g *GRPCServer) GetClusterNetworkingConfig(ctx context.Context, _ *empty.Empty) (*types.ClusterNetworkingConfigV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	netConfig, err := auth.ServerWithRoles.GetClusterNetworkingConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	netConfigV2, ok := netConfig.(*types.ClusterNetworkingConfigV2)
	if !ok {
		return nil, trace.BadParameter("unexpected type %T", netConfig)
	}
	return netConfigV2, nil
}

// SetClusterNetworkingConfig sets cluster networking configuration.
func (g *GRPCServer) SetClusterNetworkingConfig(ctx context.Context, netConfig *types.ClusterNetworkingConfigV2) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	netConfig.SetOrigin(types.OriginDynamic)
	if err = auth.ServerWithRoles.SetClusterNetworkingConfig(ctx, netConfig); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// ResetClusterNetworkingConfig resets cluster networking configuration to defaults.
func (g *GRPCServer) ResetClusterNetworkingConfig(ctx context.Context, _ *empty.Empty) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err = auth.ServerWithRoles.ResetClusterNetworkingConfig(ctx); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// GetSessionRecordingConfig gets session recording configuration.
func (g *GRPCServer) GetSessionRecordingConfig(ctx context.Context, _ *empty.Empty) (*types.SessionRecordingConfigV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	recConfig, err := auth.ServerWithRoles.GetSessionRecordingConfig(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	recConfigV2, ok := recConfig.(*types.SessionRecordingConfigV2)
	if !ok {
		return nil, trace.BadParameter("unexpected type %T", recConfig)
	}
	return recConfigV2, nil
}

// SetSessionRecordingConfig sets session recording configuration.
func (g *GRPCServer) SetSessionRecordingConfig(ctx context.Context, recConfig *types.SessionRecordingConfigV2) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	recConfig.SetOrigin(types.OriginDynamic)
	if err = auth.ServerWithRoles.SetSessionRecordingConfig(ctx, recConfig); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// ResetSessionRecordingConfig resets session recording configuration to defaults.
func (g *GRPCServer) ResetSessionRecordingConfig(ctx context.Context, _ *empty.Empty) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err = auth.ServerWithRoles.ResetSessionRecordingConfig(ctx); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// GetAuthPreference gets cluster auth preference.
func (g *GRPCServer) GetAuthPreference(ctx context.Context, _ *empty.Empty) (*types.AuthPreferenceV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	authPref, err := auth.ServerWithRoles.GetAuthPreference(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	authPrefV2, ok := authPref.(*types.AuthPreferenceV2)
	if !ok {
		return nil, trace.Wrap(trace.BadParameter("unexpected type %T", authPref))
	}
	return authPrefV2, nil
}

// SetAuthPreference sets cluster auth preference.
func (g *GRPCServer) SetAuthPreference(ctx context.Context, authPref *types.AuthPreferenceV2) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	authPref.SetOrigin(types.OriginDynamic)
	if err = auth.ServerWithRoles.SetAuthPreference(ctx, authPref); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// ResetAuthPreference resets cluster auth preference to defaults.
func (g *GRPCServer) ResetAuthPreference(ctx context.Context, _ *empty.Empty) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err = auth.ServerWithRoles.ResetAuthPreference(ctx); err != nil {
		return nil, trace.Wrap(err)
	}
	return &empty.Empty{}, nil
}

// StreamSessionEvents streams all events from a given session recording. An error is returned on the first
// channel if one is encountered. Otherwise the event channel is closed when the stream ends.
// The event channel is not closed on error to prevent race conditions in downstream select statements.
func (g *GRPCServer) StreamSessionEvents(req *proto.StreamSessionEventsRequest, stream proto.AuthService_StreamSessionEventsServer) error {
	auth, err := g.authenticate(stream.Context())
	if err != nil {
		return trace.Wrap(err)
	}

	c, e := auth.ServerWithRoles.StreamSessionEvents(stream.Context(), session.ID(req.SessionID), int64(req.StartIndex))

	for {
		select {
		case event, more := <-c:
			if !more {
				return nil
			}

			oneOf, err := apievents.ToOneOf(event)
			if err != nil {
				return trail.ToGRPC(trace.Wrap(err))
			}

			if err := stream.Send(oneOf); err != nil {
				return trail.ToGRPC(trace.Wrap(err))
			}
		case err := <-e:
			return trail.ToGRPC(trace.Wrap(err))
		}
	}
}

// GetNetworkRestrictions retrieves all the network restrictions (allow/deny lists).
func (g *GRPCServer) GetNetworkRestrictions(ctx context.Context, _ *empty.Empty) (*types.NetworkRestrictionsV4, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}
	nr, err := auth.ServerWithRoles.GetNetworkRestrictions(ctx)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}
	restrictionsV4, ok := nr.(*types.NetworkRestrictionsV4)
	if !ok {
		return nil, trace.Wrap(trace.BadParameter("unexpected type %T", nr))
	}
	return restrictionsV4, nil
}

// SetNetworkRestrictions updates the network restrictions.
func (g *GRPCServer) SetNetworkRestrictions(ctx context.Context, nr *types.NetworkRestrictionsV4) (*empty.Empty, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trail.ToGRPC(err)
	}

	if err = auth.ServerWithRoles.SetNetworkRestrictions(ctx, nr); err != nil {
		return nil, trail.ToGRPC(err)
	}
	return &empty.Empty{}, nil
}

// GetEvents searches for events on the backend and sends them back in a response.
func (g *GRPCServer) GetEvents(ctx context.Context, req *proto.GetEventsRequest) (*proto.Events, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	rawEvents, lastkey, err := auth.ServerWithRoles.SearchEvents(req.StartDate, req.EndDate, req.Namespace, req.EventTypes, int(req.Limit), types.EventOrder(req.Order), req.StartKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var res *proto.Events = &proto.Events{}

	encodedEvents := make([]*apievents.OneOf, 0, len(rawEvents))

	for _, rawEvent := range rawEvents {
		event, err := apievents.ToOneOf(rawEvent)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		encodedEvents = append(encodedEvents, event)
	}

	res.Items = encodedEvents
	res.LastKey = lastkey
	return res, nil
}

// GetSessionEvents searches for session events on the backend and sends them back in a response.
func (g *GRPCServer) GetSessionEvents(ctx context.Context, req *proto.GetSessionEventsRequest) (*proto.Events, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	rawEvents, lastkey, err := auth.ServerWithRoles.SearchSessionEvents(req.StartDate, req.EndDate, int(req.Limit), types.EventOrder(req.Order), req.StartKey, nil, "")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var res *proto.Events = &proto.Events{}

	encodedEvents := make([]*apievents.OneOf, 0, len(rawEvents))

	for _, rawEvent := range rawEvents {
		event, err := apievents.ToOneOf(rawEvent)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		encodedEvents = append(encodedEvents, event)
	}

	res.Items = encodedEvents
	res.LastKey = lastkey
	return res, nil
}

// GetLock retrieves a lock by name.
func (g *GRPCServer) GetLock(ctx context.Context, req *proto.GetLockRequest) (*types.LockV2, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lock, err := auth.GetLock(ctx, req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lockV2, ok := lock.(*types.LockV2)
	if !ok {
		return nil, trace.Errorf("unexpected lock type %T", lock)
	}
	return lockV2, nil
}

// GetLocks gets all/in-force locks that match at least one of the targets when specified.
func (g *GRPCServer) GetLocks(ctx context.Context, req *proto.GetLocksRequest) (*proto.GetLocksResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	targets := make([]types.LockTarget, 0, len(req.Targets))
	for _, targetPtr := range req.Targets {
		if targetPtr != nil {
			targets = append(targets, *targetPtr)
		}
	}
	locks, err := auth.GetLocks(ctx, req.InForceOnly, targets...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lockV2s := make([]*types.LockV2, 0, len(locks))
	for _, lock := range locks {
		lockV2, ok := lock.(*types.LockV2)
		if !ok {
			return nil, trace.BadParameter("unexpected lock type %T", lock)
		}
		lockV2s = append(lockV2s, lockV2)
	}
	return &proto.GetLocksResponse{
		Locks: lockV2s,
	}, nil
}

// GenerateCertAuthorityCRL returns a CRL for a CA.
func (g *GRPCServer) GenerateCertAuthorityCRL(ctx context.Context, req *proto.CertAuthorityRequest) (*proto.CRL, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	crl, err := auth.GenerateCertAuthorityCRL(ctx, req.Type)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &proto.CRL{CRL: crl}, nil
}

// ListResources retrieves a paginated list of resources.
func (g *GRPCServer) ListResources(ctx context.Context, req *proto.ListResourcesRequest) (*proto.ListResourcesResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := auth.ListResources(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	protoResp := &proto.ListResourcesResponse{
		NextKey:    resp.NextKey,
		Resources:  make([]*proto.PaginatedResource, len(resp.Resources)),
		TotalCount: int32(resp.TotalCount),
	}

	for i, resource := range resp.Resources {
		var protoResource *proto.PaginatedResource
		switch req.ResourceType {
		case types.KindNode:
			srv, ok := resource.(*types.ServerV2)
			if !ok {
				return nil, trace.BadParameter("node has invalid type %T", resource)
			}

			protoResource = &proto.PaginatedResource{Resource: &proto.PaginatedResource_Node{Node: srv}}
		default:
			return nil, trace.NotImplemented("resource type %s doesn't support pagination", req.ResourceType)
		}

		protoResp.Resources[i] = protoResource
	}

	return protoResp, nil
}

// GetSessionTracker returns the current state of a session tracker for an active session.
func (g *GRPCServer) GetSessionTracker(ctx context.Context, req *proto.GetSessionTrackerRequest) (*types.SessionTrackerV1, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	session, err := auth.ServerWithRoles.GetSessionTracker(ctx, req.SessionID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	defined, ok := session.(*types.SessionTrackerV1)
	if !ok {
		return nil, trace.BadParameter("unexpected session type %T", session)
	}

	return defined, nil
}

// GetActiveSessionTrackers returns a list of active session trackers.
func (g *GRPCServer) GetActiveSessionTrackers(_ *empty.Empty, stream proto.AuthService_GetActiveSessionTrackersServer) error {
	ctx := stream.Context()
	auth, err := g.authenticate(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	sessions, err := auth.ServerWithRoles.GetActiveSessionTrackers(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, session := range sessions {
		defined, ok := session.(*types.SessionTrackerV1)
		if !ok {
			return trace.BadParameter("unexpected session type %T", session)
		}

		err := stream.Send(defined)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// GetDomainName returns local auth domain of the current auth server.
func (g *GRPCServer) GetDomainName(ctx context.Context, req *empty.Empty) (*proto.GetDomainNameResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	dn, err := auth.ServerWithRoles.GetDomainName(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &proto.GetDomainNameResponse{
		DomainName: dn,
	}, nil
}

// GetClusterCACert returns the PEM-encoded TLS certs for the local cluster
// without signing keys. If the cluster has multiple TLS certs, they will all
// be appended.
func (g *GRPCServer) GetClusterCACert(
	ctx context.Context, req *empty.Empty,
) (*proto.GetClusterCACertResponse, error) {
	auth, err := g.authenticate(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return auth.ServerWithRoles.GetClusterCACert(ctx)
}

// GRPCServerConfig specifies GRPC server configuration
type GRPCServerConfig struct {
	// APIConfig is GRPC server API configuration
	APIConfig
	// TLS is GRPC server config
	TLS *tls.Config
	// UnaryInterceptor intercepts individual GRPC requests
	// for authentication and rate limiting
	UnaryInterceptor grpc.UnaryServerInterceptor
	// UnaryInterceptor intercepts GRPC streams
	// for authentication and rate limiting
	StreamInterceptor grpc.StreamServerInterceptor
}

// CheckAndSetDefaults checks and sets default values
func (cfg *GRPCServerConfig) CheckAndSetDefaults() error {
	if cfg.TLS == nil {
		return trace.BadParameter("missing parameter TLS")
	}
	if cfg.UnaryInterceptor == nil {
		return trace.BadParameter("missing parameter UnaryInterceptor")
	}
	if cfg.StreamInterceptor == nil {
		return trace.BadParameter("missing parameter StreamInterceptor")
	}
	return nil
}

// NewGRPCServer returns a new instance of GRPC server
func NewGRPCServer(cfg GRPCServerConfig) (*GRPCServer, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	log.Debugf("GRPC(SERVER): keep alive %v count: %v.", cfg.KeepAlivePeriod, cfg.KeepAliveCount)
	opts := []grpc.ServerOption{
		grpc.Creds(&httplib.TLSCreds{
			Config: cfg.TLS,
		}),
		grpc.ChainUnaryInterceptor(otelgrpc.UnaryServerInterceptor(), cfg.UnaryInterceptor),
		grpc.ChainStreamInterceptor(otelgrpc.StreamServerInterceptor(), cfg.StreamInterceptor),
		grpc.KeepaliveParams(
			keepalive.ServerParameters{
				Time:    cfg.KeepAlivePeriod,
				Timeout: cfg.KeepAlivePeriod * time.Duration(cfg.KeepAliveCount),
			},
		),
		grpc.KeepaliveEnforcementPolicy(
			keepalive.EnforcementPolicy{
				MinTime:             cfg.KeepAlivePeriod,
				PermitWithoutStream: true,
			},
		),
	}
	server := grpc.NewServer(opts...)
	authServer := &GRPCServer{
		APIConfig: cfg.APIConfig,
		Entry: logrus.WithFields(logrus.Fields{
			trace.Component: teleport.Component(teleport.ComponentAuth, teleport.ComponentGRPC),
		}),
		server: server,
	}
	//proto.RegisterAuthServiceServer(server, authServer)
	collectortracepb.RegisterTraceServiceServer(server, authServer)

	// create server with no-op role to pass to JoinService server
	serverWithNopRole, err := serverWithNopRole(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	joinServiceServer := joinserver.NewJoinServiceGRPCServer(serverWithNopRole)
	proto.RegisterJoinServiceServer(server, joinServiceServer)

	return authServer, nil
}

func serverWithNopRole(cfg GRPCServerConfig) (*ServerWithRoles, error) {
	clusterName, err := cfg.AuthServer.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	nopRole := BuiltinRole{
		Role:        types.RoleNop,
		Username:    string(types.RoleNop),
		ClusterName: clusterName.GetClusterName(),
	}
	recConfig, err := cfg.AuthServer.GetSessionRecordingConfig(context.Background())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	nopCtx, err := contextForBuiltinRole(nopRole, recConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ServerWithRoles{
		authServer: cfg.AuthServer,
		context:    *nopCtx,
		sessions:   cfg.SessionService,
		alog:       cfg.AuthServer,
	}, nil
}

type grpcContext struct {
	*Context
	*ServerWithRoles
}

// authenticate extracts authentication context and returns initialized auth server
func (g *GRPCServer) authenticate(ctx context.Context) (*grpcContext, error) {
	// HTTPS server expects auth context to be set by the auth middleware
	authContext, err := g.Authorizer.Authorize(ctx)
	if err != nil {
		// propagate connection problem error so we can differentiate
		// between connection failed and access denied
		if trace.IsConnectionProblem(err) {
			return nil, trace.ConnectionProblem(err, "[10] failed to connect to the database")
		} else if trace.IsNotFound(err) {
			// user not found, wrap error with access denied
			return nil, trace.Wrap(err, "[10] access denied")
		} else if trace.IsAccessDenied(err) {
			// don't print stack trace, just log the warning
			log.Warn(err)
		} else {
			log.Warn(trace.DebugReport(err))
		}
		return nil, trace.AccessDenied("[10] access denied")
	}
	return &grpcContext{
		Context: authContext,
		ServerWithRoles: &ServerWithRoles{
			authServer: g.AuthServer,
			context:    *authContext,
			sessions:   g.SessionService,
			alog:       g.AuthServer,
		},
	}, nil
}
