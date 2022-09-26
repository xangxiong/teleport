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

package client

// import (
// 	"context"
// 	"crypto/tls"
// 	"fmt"
// 	"net"
// 	"testing"
// 	"time"

// 	"github.com/gravitational/teleport/api/client/proto"
// 	"github.com/gravitational/teleport/api/defaults"
// 	"github.com/gravitational/teleport/api/types"

// 	"github.com/golang/protobuf/ptypes/empty"
// 	"github.com/google/go-cmp/cmp"
// 	"github.com/gravitational/trace"
// 	"github.com/gravitational/trace/trail"
// 	"github.com/stretchr/testify/require"
// 	"golang.org/x/crypto/ssh"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/codes"
// 	"google.golang.org/grpc/credentials/insecure"
// 	"google.golang.org/grpc/status"
// )

// // mockServer mocks an Auth Server.
// type mockServer struct {
// 	addr string
// 	grpc *grpc.Server
// 	*proto.UnimplementedAuthServiceServer
// }

// func newMockServer(addr string) *mockServer {
// 	m := &mockServer{
// 		addr:                           addr,
// 		grpc:                           grpc.NewServer(),
// 		UnimplementedAuthServiceServer: &proto.UnimplementedAuthServiceServer{},
// 	}
// 	proto.RegisterAuthServiceServer(m.grpc, m)
// 	return m
// }

// func (m *mockServer) Stop() {
// 	m.grpc.Stop()
// }

// func (m *mockServer) Addr() string {
// 	return m.addr
// }

// type ConfigOpt func(*Config)

// func WithConfig(cfg Config) ConfigOpt {
// 	return func(config *Config) {
// 		*config = cfg
// 	}
// }

// func (m *mockServer) NewClient(ctx context.Context, opts ...ConfigOpt) (*Client, error) {
// 	cfg := Config{
// 		Addrs: []string{m.addr},
// 		Credentials: []Credentials{
// 			&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 		},
// 		DialOpts: []grpc.DialOption{
// 			grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 		},
// 	}

// 	for _, opt := range opts {
// 		opt(&cfg)
// 	}

// 	return New(ctx, cfg)
// }

// // startMockServer starts a new mock server. Parallel tests cannot use the same addr.
// func startMockServer(t *testing.T) *mockServer {
// 	l, err := net.Listen("tcp", "")
// 	require.NoError(t, err)
// 	return startMockServerWithListener(t, l)
// }

// // startMockServerWithListener starts a new mock server with the provided listener
// func startMockServerWithListener(t *testing.T, l net.Listener) *mockServer {
// 	srv := newMockServer(l.Addr().String())
// 	t.Cleanup(srv.grpc.Stop)

// 	go func() {
// 		require.NoError(t, srv.grpc.Serve(l))
// 	}()
// 	return srv
// }

// func (m *mockServer) Ping(ctx context.Context, req *proto.PingRequest) (*proto.PingResponse, error) {
// 	return &proto.PingResponse{}, nil
// }

// func (m *mockServer) ListResources(ctx context.Context, req *proto.ListResourcesRequest) (*proto.ListResourcesResponse, error) {
// 	resources, err := testResources(req.ResourceType, req.Namespace)
// 	if err != nil {
// 		return nil, trail.ToGRPC(err)
// 	}

// 	resp := &proto.ListResourcesResponse{
// 		Resources:  make([]*proto.PaginatedResource, 0),
// 		TotalCount: int32(len(resources)),
// 	}

// 	var (
// 		takeResources    = req.StartKey == ""
// 		lastResourceName string
// 	)
// 	for _, resource := range resources {
// 		if resource.GetName() == req.StartKey {
// 			takeResources = true
// 			continue
// 		}

// 		if !takeResources {
// 			continue
// 		}

// 		var protoResource *proto.PaginatedResource
// 		switch req.ResourceType {
// 		case types.KindDatabaseServer:
// 			database, ok := resource.(*types.DatabaseServerV3)
// 			if !ok {
// 				return nil, trace.Errorf("database server has invalid type %T", resource)
// 			}

// 			protoResource = &proto.PaginatedResource{Resource: &proto.PaginatedResource_DatabaseServer{DatabaseServer: database}}
// 		case types.KindAppServer:
// 			app, ok := resource.(*types.AppServerV3)
// 			if !ok {
// 				return nil, trace.Errorf("application server has invalid type %T", resource)
// 			}

// 			protoResource = &proto.PaginatedResource{Resource: &proto.PaginatedResource_AppServer{AppServer: app}}
// 		case types.KindNode:
// 			srv, ok := resource.(*types.ServerV2)
// 			if !ok {
// 				return nil, trace.Errorf("node has invalid type %T", resource)
// 			}

// 			protoResource = &proto.PaginatedResource{Resource: &proto.PaginatedResource_Node{Node: srv}}
// 		case types.KindKubeService:
// 			srv, ok := resource.(*types.ServerV2)
// 			if !ok {
// 				return nil, trace.Errorf("kubernetes service has invalid type %T", resource)
// 			}

// 			protoResource = &proto.PaginatedResource{Resource: &proto.PaginatedResource_KubeService{KubeService: srv}}
// 		case types.KindWindowsDesktop:
// 			desktop, ok := resource.(*types.WindowsDesktopV3)
// 			if !ok {
// 				return nil, trace.Errorf("windows desktop has invalid type %T", resource)
// 			}

// 			protoResource = &proto.PaginatedResource{Resource: &proto.PaginatedResource_WindowsDesktop{WindowsDesktop: desktop}}
// 		}

// 		resp.Resources = append(resp.Resources, protoResource)
// 		lastResourceName = resource.GetName()
// 		if len(resp.Resources) == int(req.Limit) {
// 			break
// 		}
// 	}

// 	if len(resp.Resources) != len(resources) {
// 		resp.NextKey = lastResourceName
// 	}

// 	return resp, nil
// }

// func (m *mockServer) AddMFADeviceSync(ctx context.Context, req *proto.AddMFADeviceSyncRequest) (*proto.AddMFADeviceSyncResponse, error) {
// 	return nil, status.Error(codes.AlreadyExists, "Already Exists")
// }

// const fiveMBNode = "fiveMBNode"

// func testResources(resourceType, namespace string) ([]types.ResourceWithLabels, error) {
// 	var err error
// 	size := 50
// 	// Artificially make each node ~ 100KB to force
// 	// ListResources to fail with chunks of >= 40.
// 	labelSize := 100000
// 	resources := make([]types.ResourceWithLabels, size)

// 	switch resourceType {
// 	case types.KindDatabaseServer:
// 		for i := 0; i < size; i++ {
// 			resources[i], err = types.NewDatabaseServerV3(types.Metadata{
// 				Name: fmt.Sprintf("db-%d", i),
// 				Labels: map[string]string{
// 					"label": string(make([]byte, labelSize)),
// 				},
// 			}, types.DatabaseServerSpecV3{
// 				Protocol: "",
// 				URI:      "localhost:5432",
// 				Hostname: "localhost",
// 				HostID:   fmt.Sprintf("host-%d", i),
// 			})

// 			if err != nil {
// 				return nil, trace.Wrap(err)
// 			}
// 		}
// 	case types.KindAppServer:
// 		for i := 0; i < size; i++ {
// 			app, err := types.NewAppV3(types.Metadata{
// 				Name: fmt.Sprintf("app-%d", i),
// 			}, types.AppSpecV3{
// 				URI: "localhost",
// 			})
// 			if err != nil {
// 				return nil, trace.Wrap(err)
// 			}

// 			resources[i], err = types.NewAppServerV3(types.Metadata{
// 				Name: fmt.Sprintf("app-%d", i),
// 				Labels: map[string]string{
// 					"label": string(make([]byte, labelSize)),
// 				},
// 			}, types.AppServerSpecV3{
// 				HostID: fmt.Sprintf("host-%d", i),
// 				App:    app,
// 			})

// 			if err != nil {
// 				return nil, trace.Wrap(err)
// 			}
// 		}
// 	case types.KindNode:
// 		for i := 0; i < size; i++ {
// 			nodeLabelSize := labelSize
// 			if namespace == fiveMBNode && i == 0 {
// 				// Artificially make a node ~ 5MB to force
// 				// ListNodes to fail regardless of chunk size.
// 				nodeLabelSize = 5000000
// 			}

// 			var err error
// 			resources[i], err = types.NewServerWithLabels(fmt.Sprintf("node-%d", i), types.KindNode, types.ServerSpecV2{},
// 				map[string]string{
// 					"label": string(make([]byte, nodeLabelSize)),
// 				},
// 			)
// 			if err != nil {
// 				return nil, trace.Wrap(err)
// 			}
// 		}
// 	case types.KindKubeService:
// 		for i := 0; i < size; i++ {
// 			var err error
// 			name := fmt.Sprintf("kube-service-%d", i)
// 			resources[i], err = types.NewServerWithLabels(name, types.KindKubeService, types.ServerSpecV2{
// 				KubernetesClusters: []*types.KubernetesCluster{
// 					{Name: name, StaticLabels: map[string]string{"name": name}},
// 				},
// 			}, map[string]string{
// 				"label": string(make([]byte, labelSize)),
// 			})

// 			if err != nil {
// 				return nil, trace.Wrap(err)
// 			}
// 		}
// 	case types.KindWindowsDesktop:
// 		for i := 0; i < size; i++ {
// 			var err error
// 			name := fmt.Sprintf("windows-desktop-%d", i)
// 			resources[i], err = types.NewWindowsDesktopV3(
// 				name,
// 				map[string]string{"label": string(make([]byte, labelSize))},
// 				types.WindowsDesktopSpecV3{
// 					Addr:   "_",
// 					HostID: "_",
// 				})
// 			if err != nil {
// 				return nil, trace.Wrap(err)
// 			}
// 		}

// 	default:
// 		return nil, trace.Errorf("unsupported resource type %s", resourceType)
// 	}

// 	return resources, nil
// }

// // mockInsecureCredentials mocks insecure Client credentials.
// // it returns a nil tlsConfig which allows the client to run in insecure mode.
// // TODO(Joerger) replace insecure credentials with proper TLS credentials.
// type mockInsecureTLSCredentials struct{}

// func (mc *mockInsecureTLSCredentials) Dialer(cfg Config) (ContextDialer, error) {
// 	return nil, trace.NotImplemented("no dialer")
// }

// func (mc *mockInsecureTLSCredentials) TLSConfig() (*tls.Config, error) {
// 	return nil, nil
// }

// func (mc *mockInsecureTLSCredentials) SSHClientConfig() (*ssh.ClientConfig, error) {
// 	return nil, trace.NotImplemented("no ssh config")
// }

// func TestNew(t *testing.T) {
// 	t.Parallel()
// 	ctx := context.Background()
// 	srv := startMockServer(t)

// 	tests := []struct {
// 		desc      string
// 		config    Config
// 		assertErr require.ErrorAssertionFunc
// 	}{{
// 		desc: "successfully dial tcp address.",
// 		config: Config{
// 			Addrs: []string{srv.Addr()},
// 			Credentials: []Credentials{
// 				&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 			},
// 			DialOpts: []grpc.DialOption{
// 				grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 			},
// 		},
// 		assertErr: require.NoError,
// 	}, {
// 		desc: "synchronously dial addr/cred pairs and succeed with the 1 good pair.",
// 		config: Config{
// 			Addrs: []string{"bad addr", srv.Addr(), "bad addr"},
// 			Credentials: []Credentials{
// 				&tlsConfigCreds{nil},
// 				&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 				&tlsConfigCreds{nil},
// 			},
// 			DialOpts: []grpc.DialOption{
// 				grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 			},
// 		},
// 		assertErr: require.NoError,
// 	}, {
// 		desc: "fail to dial with a bad address.",
// 		config: Config{
// 			DialTimeout: time.Second,
// 			Addrs:       []string{"bad addr"},
// 			Credentials: []Credentials{
// 				&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 			},
// 			DialOpts: []grpc.DialOption{
// 				grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 			},
// 		},
// 		assertErr: func(t require.TestingT, err error, _ ...interface{}) {
// 			require.Error(t, err)
// 			require.Contains(t, err.Error(), "all connection methods failed")
// 		},
// 	}, {
// 		desc: "fail to dial with no address or dialer.",
// 		config: Config{
// 			DialTimeout: time.Second,
// 			Credentials: []Credentials{
// 				&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 			},
// 			DialOpts: []grpc.DialOption{
// 				grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 			},
// 		},
// 		assertErr: func(t require.TestingT, err error, _ ...interface{}) {
// 			require.Error(t, err)
// 			require.Contains(t, err.Error(), "no connection methods found, try providing Dialer or Addrs in config")
// 		},
// 	}}

// 	for _, tt := range tests {
// 		t.Run(tt.desc, func(t *testing.T) {
// 			clt, err := srv.NewClient(ctx, WithConfig(tt.config))
// 			tt.assertErr(t, err)

// 			if err == nil {
// 				t.Cleanup(func() { require.NoError(t, clt.Close()) })
// 				// requests to the server should succeed.
// 				_, err = clt.Ping(ctx)
// 				require.NoError(t, err)
// 			}
// 		})
// 	}
// }

// func TestNewDialBackground(t *testing.T) {
// 	t.Parallel()
// 	ctx := context.Background()

// 	// get listener but don't serve it yet.
// 	l, err := net.Listen("tcp", "")
// 	require.NoError(t, err)
// 	addr := l.Addr().String()

// 	// Create client before the server is listening.
// 	clt, err := New(ctx, Config{
// 		DialInBackground: true,
// 		Addrs:            []string{addr},
// 		Credentials: []Credentials{
// 			&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 		},
// 		DialOpts: []grpc.DialOption{
// 			grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 		},
// 	})
// 	require.NoError(t, err)
// 	t.Cleanup(func() { require.NoError(t, clt.Close()) })

// 	// requests to the server will result in a connection error.
// 	cancelCtx, cancel := context.WithTimeout(ctx, time.Second*3)
// 	defer cancel()
// 	_, err = clt.Ping(cancelCtx)
// 	require.Error(t, err)

// 	// Start the server and wait for the client connection to be ready.
// 	startMockServerWithListener(t, l)
// 	require.NoError(t, clt.waitForConnectionReady(ctx))

// 	// requests to the server should succeed.
// 	_, err = clt.Ping(ctx)
// 	require.NoError(t, err)
// }

// func TestWaitForConnectionReady(t *testing.T) {
// 	t.Parallel()
// 	ctx := context.Background()

// 	l, err := net.Listen("tcp", "")
// 	require.NoError(t, err)
// 	addr := l.Addr().String()

// 	// Create client before the server is listening.
// 	clt, err := New(ctx, Config{
// 		DialInBackground: true,
// 		Addrs:            []string{addr},
// 		Credentials: []Credentials{
// 			&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 		},
// 		DialOpts: []grpc.DialOption{
// 			grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 		},
// 	})
// 	require.NoError(t, err)
// 	t.Cleanup(func() { require.NoError(t, clt.Close()) })

// 	// WaitForConnectionReady should return false once the
// 	// context is canceled if the server isn't open to connections.
// 	cancelCtx, cancel := context.WithTimeout(ctx, time.Second*3)
// 	defer cancel()
// 	require.Error(t, clt.waitForConnectionReady(cancelCtx))

// 	// WaitForConnectionReady should return nil if the server is open to connections.
// 	startMockServerWithListener(t, l)
// 	require.NoError(t, clt.waitForConnectionReady(ctx))

// 	// WaitForConnectionReady should return an error if the grpc connection is closed.
// 	require.NoError(t, clt.Close())
// 	require.Error(t, clt.waitForConnectionReady(ctx))
// }

// func TestListResources(t *testing.T) {
// 	t.Parallel()
// 	ctx := context.Background()
// 	srv := startMockServer(t)

// 	testCases := map[string]struct {
// 		resourceType   string
// 		resourceStruct types.Resource
// 	}{
// 		"DatabaseServer": {
// 			resourceType:   types.KindDatabaseServer,
// 			resourceStruct: &types.DatabaseServerV3{},
// 		},
// 		"ApplicationServer": {
// 			resourceType:   types.KindAppServer,
// 			resourceStruct: &types.AppServerV3{},
// 		},
// 		"Node": {
// 			resourceType:   types.KindNode,
// 			resourceStruct: &types.ServerV2{},
// 		},
// 		"KubeService": {
// 			resourceType:   types.KindKubeService,
// 			resourceStruct: &types.ServerV2{},
// 		},
// 		"WindowsDesktop": {
// 			resourceType:   types.KindWindowsDesktop,
// 			resourceStruct: &types.WindowsDesktopV3{},
// 		},
// 	}

// 	// Create client
// 	clt, err := srv.NewClient(ctx)
// 	require.NoError(t, err)

// 	for name, test := range testCases {
// 		t.Run(name, func(t *testing.T) {
// 			resp, err := clt.ListResources(ctx, proto.ListResourcesRequest{
// 				Namespace:    defaults.Namespace,
// 				Limit:        10,
// 				ResourceType: test.resourceType,
// 			})
// 			require.NoError(t, err)
// 			require.NotEmpty(t, resp.NextKey)
// 			require.Len(t, resp.Resources, 10)
// 			require.IsType(t, test.resourceStruct, resp.Resources[0])

// 			// exceed the limit
// 			_, err = clt.ListResources(ctx, proto.ListResourcesRequest{
// 				Namespace:    defaults.Namespace,
// 				Limit:        50,
// 				ResourceType: test.resourceType,
// 			})
// 			require.Error(t, err)
// 			require.IsType(t, &trace.LimitExceededError{}, err.(*trace.TraceErr).OrigError())
// 		})
// 	}

// 	// Test a list with total count returned.
// 	resp, err := clt.ListResources(ctx, proto.ListResourcesRequest{
// 		ResourceType:   types.KindNode,
// 		Limit:          10,
// 		NeedTotalCount: true,
// 	})
// 	require.NoError(t, err)
// 	require.Equal(t, 50, resp.TotalCount)
// }

// func TestGetResources(t *testing.T) {
// 	t.Parallel()
// 	ctx := context.Background()
// 	srv := startMockServer(t)

// 	// Create client
// 	clt, err := srv.NewClient(ctx)
// 	require.NoError(t, err)

// 	testCases := map[string]struct {
// 		resourceType string
// 	}{
// 		"DatabaseServer": {
// 			resourceType: types.KindDatabaseServer,
// 		},
// 		"ApplicationServer": {
// 			resourceType: types.KindAppServer,
// 		},
// 		"Node": {
// 			resourceType: types.KindNode,
// 		},
// 		"KubeService": {
// 			resourceType: types.KindKubeService,
// 		},
// 		"WindowsDesktop": {
// 			resourceType: types.KindWindowsDesktop,
// 		},
// 	}

// 	for name, test := range testCases {
// 		t.Run(name, func(t *testing.T) {
// 			expectedResources, err := testResources(test.resourceType, defaults.Namespace)
// 			require.NoError(t, err)

// 			// Test listing everything at once errors with limit exceeded.
// 			_, err = clt.ListResources(ctx, proto.ListResourcesRequest{
// 				Namespace:    defaults.Namespace,
// 				Limit:        int32(len(expectedResources)),
// 				ResourceType: test.resourceType,
// 			})
// 			require.Error(t, err)
// 			require.IsType(t, &trace.LimitExceededError{}, err.(*trace.TraceErr).OrigError())

// 			// Test getting all resources by chunks to handle limit exceeded.
// 			resources, err := GetResourcesWithFilters(ctx, clt, proto.ListResourcesRequest{
// 				Namespace:    defaults.Namespace,
// 				ResourceType: test.resourceType,
// 			})
// 			require.NoError(t, err)
// 			require.Len(t, resources, len(expectedResources))
// 			require.Empty(t, cmp.Diff(expectedResources, resources))
// 		})
// 	}
// }

// type mockOIDCConnectorServer struct {
// 	*mockServer
// 	connectors map[string]*types.OIDCConnectorV3
// }

// func newMockOIDCConnectorServer() *mockOIDCConnectorServer {
// 	m := &mockOIDCConnectorServer{
// 		&mockServer{
// 			grpc:                           grpc.NewServer(),
// 			UnimplementedAuthServiceServer: &proto.UnimplementedAuthServiceServer{},
// 		},
// 		make(map[string]*types.OIDCConnectorV3),
// 	}
// 	proto.RegisterAuthServiceServer(m.grpc, m)
// 	return m
// }

// func startMockOIDCConnectorServer(t *testing.T) string {
// 	l, err := net.Listen("tcp", "")
// 	require.NoError(t, err)
// 	t.Cleanup(func() { require.NoError(t, l.Close()) })
// 	go newMockOIDCConnectorServer().grpc.Serve(l)
// 	return l.Addr().String()
// }

// func (m *mockOIDCConnectorServer) GetOIDCConnector(ctx context.Context, req *types.ResourceWithSecretsRequest) (*types.OIDCConnectorV3, error) {
// 	conn, ok := m.connectors[req.Name]
// 	if !ok {
// 		return nil, trace.NotFound("not found")
// 	}
// 	return conn, nil
// }

// func (m *mockOIDCConnectorServer) GetOIDCConnectors(ctx context.Context, req *types.ResourcesWithSecretsRequest) (*types.OIDCConnectorV3List, error) {
// 	var connectors []*types.OIDCConnectorV3
// 	for _, conn := range m.connectors {
// 		connectors = append(connectors, conn)
// 	}
// 	return &types.OIDCConnectorV3List{
// 		OIDCConnectors: connectors,
// 	}, nil
// }

// func (m *mockOIDCConnectorServer) UpsertOIDCConnector(ctx context.Context, oidcConnector *types.OIDCConnectorV3) (*empty.Empty, error) {
// 	m.connectors[oidcConnector.Metadata.Name] = oidcConnector
// 	return &empty.Empty{}, nil
// }

// // Test that client will perform properly with an old server
// // DELETE IN 11.0.0
// func TestSetOIDCRedirectURLBackwardsCompatibility(t *testing.T) {
// 	ctx := context.Background()
// 	addr := startMockOIDCConnectorServer(t)

// 	// Create client
// 	clt, err := New(ctx, Config{
// 		Addrs: []string{addr},
// 		Credentials: []Credentials{
// 			&mockInsecureTLSCredentials{}, // TODO(Joerger) replace insecure credentials
// 		},
// 		DialOpts: []grpc.DialOption{
// 			grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO(Joerger) remove insecure dial option
// 		},
// 	})
// 	require.NoError(t, err)

// 	conn := &types.OIDCConnectorV3{
// 		Metadata: types.Metadata{
// 			Name: "one",
// 		},
// 	}

// 	// Upsert should set "RedirectURL" on the provided connector if empty
// 	conn.Spec.RedirectURLs = []string{"one.example.com"}
// 	conn.Spec.RedirectURL = ""
// 	err = clt.UpsertOIDCConnector(ctx, conn)
// 	require.NoError(t, err)
// 	require.Equal(t, 1, len(conn.GetRedirectURLs()))
// 	require.Equal(t, conn.GetRedirectURLs()[0], conn.Spec.RedirectURL)

// 	// GetOIDCConnector should set "RedirectURLs" on the received connector if empty
// 	conn.Spec.RedirectURLs = []string{}
// 	conn.Spec.RedirectURL = "one.example.com"
// 	connResp, err := clt.GetOIDCConnector(ctx, conn.GetName(), false)
// 	require.NoError(t, err)
// 	require.Equal(t, 1, len(connResp.GetRedirectURLs()))
// 	require.Equal(t, connResp.GetRedirectURLs()[0], "one.example.com")

// 	// GetOIDCConnectors should set "RedirectURLs" on the received connectors if empty
// 	conn.Spec.RedirectURLs = []string{}
// 	conn.Spec.RedirectURL = "one.example.com"
// 	connectorsResp, err := clt.GetOIDCConnectors(ctx, false)
// 	require.NoError(t, err)
// 	require.Equal(t, 1, len(connectorsResp))
// 	require.Equal(t, 1, len(connectorsResp[0].GetRedirectURLs()))
// 	require.Equal(t, "one.example.com", connectorsResp[0].GetRedirectURLs()[0])
// }

// type mockAccessRequestServer struct {
// 	*mockServer
// }

// func (g *mockAccessRequestServer) GetAccessRequests(ctx context.Context, f *types.AccessRequestFilter) (*proto.AccessRequests, error) {
// 	req, err := types.NewAccessRequest("foo", "bob", "admin")
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}

// 	return &proto.AccessRequests{
// 		AccessRequests: []*types.AccessRequestV3{req.(*types.AccessRequestV3)},
// 	}, nil
// }

// // TestAccessRequestDowngrade tests that the client will downgrade to the non stream API for fetching access requests
// // if the stream API is not available.
// func TestAccessRequestDowngrade(t *testing.T) {
// 	ctx := context.Background()
// 	l, err := net.Listen("tcp", "")
// 	require.NoError(t, err)

// 	m := &mockAccessRequestServer{
// 		&mockServer{
// 			addr:                           l.Addr().String(),
// 			grpc:                           grpc.NewServer(),
// 			UnimplementedAuthServiceServer: &proto.UnimplementedAuthServiceServer{},
// 		},
// 	}
// 	proto.RegisterAuthServiceServer(m.grpc, m)
// 	t.Cleanup(m.grpc.Stop)

// 	remoteErr := make(chan error)
// 	go func() {
// 		remoteErr <- m.grpc.Serve(l)
// 	}()

// 	clt, err := m.NewClient(ctx)
// 	require.NoError(t, err)

// 	items, err := clt.GetAccessRequests(ctx, types.AccessRequestFilter{})
// 	require.NoError(t, err)
// 	require.Len(t, items, 1)
// 	m.grpc.Stop()
// 	require.NoError(t, <-remoteErr)
// }
