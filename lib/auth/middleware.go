/*
Copyright 2017-2021 Gravitational, Inc.

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
	"crypto/tls"
	"net"
	"net/http"

	"github.com/gravitational/teleport"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/multiplexer"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// TLSServerConfig is a configuration for TLS server
type TLSServerConfig struct {
	// Listener is a listener to bind to
	Listener net.Listener
	// TLS is a base TLS configuration
	TLS *tls.Config
	// API is API server configuration
	APIConfig
	// LimiterConfig is limiter config
	LimiterConfig limiter.Config
	// AccessPoint is a caching access point
	AccessPoint AccessCache
	// Component is used for debugging purposes
	Component string
	// AcceptedUsage restricts authentication
	// to a subset of certificates based on the metadata
	AcceptedUsage []string
	// ID is an optional debugging ID
	ID string
}

// CheckAndSetDefaults checks and sets default values
func (c *TLSServerConfig) CheckAndSetDefaults() error {
	if err := c.APIConfig.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if c.Listener == nil {
		return trace.BadParameter("missing parameter Listener")
	}
	if c.TLS == nil {
		return trace.BadParameter("missing parameter TLS")
	}
	c.TLS.ClientAuth = tls.VerifyClientCertIfGiven
	if c.TLS.ClientCAs == nil {
		return trace.BadParameter("missing parameter TLS.ClientCAs")
	}
	if c.TLS.RootCAs == nil {
		return trace.BadParameter("missing parameter TLS.RootCAs")
	}
	if len(c.TLS.Certificates) == 0 {
		return trace.BadParameter("missing parameter TLS.Certificates")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("missing parameter AccessPoint")
	}
	if c.Component == "" {
		c.Component = teleport.ComponentAuth
	}
	return nil
}

// TLSServer is TLS auth server
type TLSServer struct {
	// httpServer is HTTP/1.1 part of the server
	httpServer *http.Server
	// grpcServer is GRPC server
	grpcServer *GRPCServer
	// cfg is TLS server configuration used for auth server
	cfg TLSServerConfig
	// log is TLS server logging entry
	log *logrus.Entry
	// mux is a listener that multiplexes HTTP/2 and HTTP/1.1
	// on different listeners
	mux *multiplexer.TLSListener
}

// NewTLSServer returns new unstarted TLS server
func NewTLSServer(cfg TLSServerConfig) (*TLSServer, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	// limiter limits requests by frequency and amount of simultaneous
	// connections per client
	limiter, err := limiter.NewLimiter(cfg.LimiterConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// force client auth if given
	cfg.TLS.ClientAuth = tls.VerifyClientCertIfGiven
	cfg.TLS.NextProtos = []string{http2.NextProtoTLS}

	server := &TLSServer{
		cfg: cfg,
		httpServer: &http.Server{
			Handler:           httplib.MakeTracingHandler(limiter, teleport.ComponentAuth),
			ReadHeaderTimeout: apidefaults.DefaultDialTimeout,
		},
		log: logrus.WithFields(logrus.Fields{
			trace.Component: cfg.Component,
		}),
	}

	server.grpcServer, err = NewGRPCServer(GRPCServerConfig{
		TLS:       server.cfg.TLS,
		APIConfig: cfg.APIConfig,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	server.mux, err = multiplexer.NewTLSListener(multiplexer.TLSListenerConfig{
		Listener: tls.NewListener(cfg.Listener, server.cfg.TLS),
		ID:       cfg.ID,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.PluginRegistry != nil {
		if err := cfg.PluginRegistry.RegisterAuthServices(server.grpcServer); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return server, nil
}
