/*
Copyright 2022 Gravitational, Inc.

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
package reversetunnel

import (
	"net"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus"
)

type dialType string

const (
	// direct is a direct dialed connection.
	direct dialType = "direct"
	// peer is a connection established through a peer proxy.
	peer dialType = "peer"
	// tunnel is a connection established over a local reverse tunnel initiated
	// by a client.
	tunnel dialType = "tunnel"
	// peerTunnel is a connection established over a local reverse tunnel
	// initiated by a peer proxy.
	peerTunnel dialType = "peer-tunnel"
)

// metricConn reports metrics for reversetunnel connections.
type metricConn struct {
	net.Conn
	clock clockwork.Clock

	// start is the time since the last state was reported.
	start    time.Time
	firstUse sync.Once
	dialType dialType
}

// newMetricConn returns a new metricConn
func newMetricConn(conn net.Conn, dt dialType, start time.Time, clock clockwork.Clock) *metricConn {
	c := &metricConn{
		Conn:     conn,
		dialType: dt,
		start:    start,
		clock:    clock,
	}

	connLatency.WithLabelValues(string(c.dialType), "established").Observe(c.duration().Seconds())
	return c
}

// duration returns the duration since c.start and updates c.start to now.
func (c *metricConn) duration() time.Duration {
	now := c.clock.Now()
	d := now.Sub(c.start)
	c.start = now
	return d
}

// Read wraps a net.Conn.Read to report the time between the connection being established
// and the connection being used.
func (c *metricConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.firstUse.Do(func() {
		connLatency.WithLabelValues(string(c.dialType), "first_read").Observe(c.duration().Seconds())
	})
	return n, err
}

var (
	connLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "reversetunnel_conn_latency",
			Help: "Latency metrics for reverse tunnel connections",
			// lowest bucket start of upper bound 0.001 sec (1 ms) with factor 2
			// highest bucket start of 0.001 sec * 2^15 == 32.768 sec
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 16),
		},
		[]string{"dial_type", "state"},
	)
)
