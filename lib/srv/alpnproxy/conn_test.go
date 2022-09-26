// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package alpnproxy

// import (
// 	"bytes"
// 	"context"
// 	"crypto/tls"
// 	"errors"
// 	"fmt"
// 	"io"
// 	"math"
// 	"net"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/require"
// )

// func TestPingConnection(t *testing.T) {
// 	t.Run("BufferSize", func(t *testing.T) {
// 		nWrites := 10
// 		dataWritten := []byte("message")

// 		for _, tt := range []struct {
// 			desc    string
// 			bufSize int
// 		}{
// 			{desc: "Same", bufSize: len(dataWritten)},
// 			{desc: "Large", bufSize: len(dataWritten) * 2},
// 			{desc: "Short", bufSize: len(dataWritten) / 2},
// 		} {
// 			t.Run(tt.desc, func(t *testing.T) {
// 				r, w := makePingConn(t)

// 				// Write routine
// 				errChan := make(chan error, 2)
// 				go func() {
// 					defer w.Close()

// 					for i := 0; i < nWrites; i++ {
// 						// Eventually write some pings.
// 						if i%2 == 0 {
// 							err := w.WritePing()
// 							if err != nil {
// 								errChan <- err
// 								return
// 							}
// 						}

// 						_, err := w.Write(dataWritten)
// 						if err != nil {
// 							errChan <- err
// 							return
// 						}
// 					}

// 					errChan <- nil
// 				}()

// 				// Read routine.
// 				go func() {
// 					defer r.Close()

// 					buf := make([]byte, tt.bufSize)

// 					for i := 0; i < nWrites; i++ {
// 						var (
// 							aggregator []byte
// 							n          int
// 							err        error
// 						)

// 						for n < len(dataWritten) {
// 							n, err = r.Read(buf)
// 							if err != nil {
// 								errChan <- err
// 								return
// 							}

// 							aggregator = append(aggregator, buf[:n]...)
// 						}

// 						if !bytes.Equal(dataWritten, aggregator) {
// 							errChan <- fmt.Errorf("wrong content read, expected '%s', got '%s'", string(dataWritten), string(buf[:n]))
// 							return
// 						}
// 					}

// 					errChan <- nil
// 				}()

// 				// Expect routines to finish.
// 				timer := time.NewTimer(10 * time.Second)
// 				defer timer.Stop()
// 				for i := 0; i < 1; i++ {
// 					select {
// 					case err := <-errChan:
// 						require.NoError(t, err)
// 					case <-timer.C:
// 						require.Fail(t, "routing didn't finished in time")
// 					}
// 				}
// 			})
// 		}
// 	})

// 	// Given a connection, read from it concurrently, asserting all content
// 	// written is read.
// 	//
// 	// Messages can be out of order due to concurrent reads. Other tests must
// 	// guarantee message ordering.
// 	t.Run("ConcurrentReads", func(t *testing.T) {
// 		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 		defer cancel()

// 		// Number of writes performed.
// 		nWrites := 10
// 		// Data that is going to be written/read on the connection.
// 		dataWritten := []byte("message")
// 		// Size of each read call.
// 		readSize := 2
// 		// Number of reads necessary to read the full message
// 		readNum := int(math.Ceil(float64(len(dataWritten)) / float64(readSize)))

// 		r, w := makePingConn(t)
// 		defer r.Close()
// 		defer w.Close()

// 		readChan := make(chan []byte)

// 		// Write routine
// 		go func() {
// 			for i := 0; i < nWrites; i++ {
// 				_, err := w.Write(dataWritten)
// 				if err != nil {
// 					return
// 				}
// 			}
// 		}()

// 		// Read routines.
// 		for i := 0; i < nWrites/2; i++ {
// 			go func() {
// 				buf := make([]byte, readSize)
// 				for {
// 					n, err := r.Read(buf)
// 					if err != nil && !errors.Is(err, io.EOF) {
// 						require.Fail(t, "Failed to read from connection: %v", err)
// 					}

// 					chanBytes := make([]byte, n)
// 					copy(chanBytes, buf[:n])
// 					readChan <- chanBytes
// 				}
// 			}()
// 		}

// 		var aggregator []byte
// 		for i := 0; i < nWrites; i++ {
// 			for j := 0; j < readNum; j++ {
// 				select {
// 				case <-ctx.Done():
// 					require.Fail(t, "Failed to read message (context timeout)")
// 				case data := <-readChan:
// 					aggregator = append(aggregator, data...)
// 				}
// 			}
// 		}

// 		require.Len(t, aggregator, len(dataWritten)*nWrites, "Wrong messages written")
// 	})

// 	t.Run("ConcurrentWrites", func(t *testing.T) {
// 		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 		defer cancel()

// 		w, r := makeBufferedPingConn(t)
// 		defer w.Close()
// 		defer r.Close()

// 		nWrites := 10
// 		dataWritten := []byte("message")
// 		writeChan := make(chan error)

// 		// Start write routines.
// 		for i := 0; i < nWrites/2; i++ {
// 			go func() {
// 				for writes := 0; writes < 2; writes++ {
// 					err := w.WritePing()
// 					if err != nil {
// 						writeChan <- err
// 						return
// 					}

// 					_, err = w.Write(dataWritten)
// 					if err != nil {
// 						writeChan <- err
// 						return
// 					}
// 				}

// 				writeChan <- nil
// 			}()
// 		}

// 		// Expect all writes to succeed.
// 		for i := 0; i < nWrites/2; i++ {
// 			select {
// 			case <-ctx.Done():
// 				require.Fail(t, "timout write")
// 			case err := <-writeChan:
// 				require.NoError(t, err)
// 			}
// 		}

// 		// Read all messages.
// 		buf := make([]byte, len(dataWritten))
// 		for i := 0; i < nWrites; i++ {
// 			n, err := r.Read(buf)
// 			require.NoError(t, err)
// 			require.Equal(t, dataWritten, buf[:n])
// 		}
// 	})
// }

// // makePingConn creates a piped ping connection.
// func makePingConn(t *testing.T) (*PingConn, *PingConn) {
// 	t.Helper()

// 	writer, reader := net.Pipe()
// 	tlsWriter, tlsReader := makeTLSConn(t, writer, reader)

// 	return NewPingConn(tlsWriter), NewPingConn(tlsReader)
// }

// // makeBufferedPingConn creates connections to have asynchronous writes.
// func makeBufferedPingConn(t *testing.T) (*PingConn, *PingConn) {
// 	t.Helper()

// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()

// 	l, err := net.Listen("tcp", "localhost:0")
// 	require.NoError(t, err)

// 	connChan := make(chan struct {
// 		net.Conn
// 		error
// 	}, 2)

// 	// Accept
// 	go func() {
// 		conn, err := l.Accept()
// 		connChan <- struct {
// 			net.Conn
// 			error
// 		}{conn, err}
// 	}()

// 	// Dial
// 	go func() {
// 		conn, err := net.Dial("tcp", l.Addr().String())
// 		connChan <- struct {
// 			net.Conn
// 			error
// 		}{conn, err}
// 	}()

// 	connSlice := make([]net.Conn, 2)
// 	for i := 0; i < 2; i++ {
// 		select {
// 		case <-ctx.Done():
// 			require.Fail(t, "failed waiting for connections")
// 		case res := <-connChan:
// 			require.NoError(t, res.error)
// 			connSlice[i] = res.Conn
// 		}
// 	}

// 	tlsConnA, tlsConnB := makeTLSConn(t, connSlice[0], connSlice[1])
// 	return NewPingConn(tlsConnA), NewPingConn(tlsConnB)
// }

// // makeTLSConn take two connections (client and server) and wrap them into TLS
// // connections.
// func makeTLSConn(t *testing.T, server, client net.Conn) (*tls.Conn, *tls.Conn) {
// 	tlsConnChan := make(chan struct {
// 		*tls.Conn
// 		error
// 	}, 2)
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()

// 	// Server
// 	go func() {
// 		tlsConn := tls.Server(server, &tls.Config{
// 			Certificates: []tls.Certificate{mustGenCertSignedWithCA(t, mustGenSelfSignedCert(t))},
// 		})
// 		tlsConnChan <- struct {
// 			*tls.Conn
// 			error
// 		}{tlsConn, tlsConn.Handshake()}
// 	}()

// 	// Client
// 	go func() {
// 		tlsConn := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
// 		tlsConnChan <- struct {
// 			*tls.Conn
// 			error
// 		}{tlsConn, tlsConn.Handshake()}
// 	}()

// 	tlsConnSlice := make([]*tls.Conn, 2)
// 	for i := 0; i < 2; i++ {
// 		select {
// 		case <-ctx.Done():
// 			server.Close()
// 			client.Close()

// 			require.Fail(t, "failed waiting for TLS connections", "%d connections remaining", 2-i)
// 		case res := <-tlsConnChan:
// 			require.NoError(t, res.error)
// 			tlsConnSlice[i] = res.Conn
// 		}
// 	}

// 	return tlsConnSlice[0], tlsConnSlice[1]
// }
