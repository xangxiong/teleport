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

package alpnproxyauth

// import (
// 	"context"
// 	"net"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/require"
// )

// func TestDialLocalAuthServerNoServers(t *testing.T) {
// 	s := NewAuthProxyDialerService(nil /* reverseTunnelServer */, "clustername", nil /* authServers */)
// 	_, err := s.dialLocalAuthServer(context.Background())
// 	require.Error(t, err, "dialLocalAuthServer expected to fail")
// 	require.Equal(t, "empty auth servers list", err.Error())
// }

// func TestDialLocalAuthServerNoAvailableServers(t *testing.T) {
// 	s := NewAuthProxyDialerService(nil /* reverseTunnelServer */, "clustername", []string{"0.0.0.0:3025"})
// 	_, err := s.dialLocalAuthServer(context.Background())
// 	require.Error(t, err, "dialLocalAuthServer expected to fail")
// 	var netErr *net.OpError
// 	require.ErrorAs(t, err, &netErr)
// 	require.Equal(t, "dial", netErr.Op)
// 	require.Equal(t, "0.0.0.0:3025", netErr.Addr.String())
// }

// func TestDialLocalAuthServerAvailableServers(t *testing.T) {
// 	socket, err := net.Listen("tcp", "127.0.0.1:")
// 	require.NoError(t, err)
// 	t.Cleanup(func() { require.NoError(t, socket.Close()) })

// 	authServers := make([]string, 1, 11)
// 	authServers[0] = socket.Addr().String()
// 	// multiple invalid servers to minimize chance that we select good one first try
// 	for i := 0; i < 10; i++ {
// 		authServers = append(authServers, "0.0.0.0:3025")
// 	}
// 	s := NewAuthProxyDialerService(nil /* reverseTunnelServer */, "clustername", authServers)
// 	require.Eventually(t, func() bool {
// 		conn, err := s.dialLocalAuthServer(context.Background())
// 		if err != nil {
// 			return false
// 		}
// 		conn.Close()
// 		return true
// 	}, 5*time.Second, 10*time.Millisecond)
// }
