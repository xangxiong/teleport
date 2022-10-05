/*
Copyright 2015 Gravitational, Inc.

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

// Package config provides facilities for configuring Teleport daemons
// including
//   - parsing YAML configuration
//   - parsing CLI flags
package config

import (
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	log "github.com/sirupsen/logrus"
)

// CommandLineFlags stores command line flag values, it's a much simplified subset
// of Teleport configuration (which is fully expressed via YAML config file)
type CommandLineFlags struct {
	// --name flag
	NodeName string
	// --auth-server flag
	AuthServerAddr []string
	// --token flag
	AuthToken string
	// CAPins are the SKPI hashes of the CAs used to verify the Auth Server.
	CAPins []string
	// --listen-ip flag
	ListenIP net.IP
	// --advertise-ip flag
	AdvertiseIP string
	// --roles flag
	Roles string
	// -d flag
	Debug bool

	// --insecure-no-tls flag
	DisableTLS bool

	// --labels flag
	Labels string
	// --pid-file flag
	PIDFile string
	// PermitUserEnvironment enables reading of ~/.tsh/environment
	// when creating a new session.
	PermitUserEnvironment bool

	// Insecure mode is controlled by --insecure flag and in this mode
	// Teleport won't check certificates when connecting to trusted clusters
	// It's useful for learning Teleport (following quick starts, etc).
	InsecureMode bool

	// FIPS mode means Teleport starts in a FedRAMP/FIPS 140-2 compliant
	// configuration.
	FIPS bool

	// SkipVersionCheck allows Teleport to connect to auth servers that
	// have an earlier major version number.
	SkipVersionCheck bool
}

// Configure merges command line arguments with what's in a configuration file
// with CLI commands taking precedence
func Configure(clf *CommandLineFlags, cfg *service.Config) error {
	// pass the value of --insecure flag to the runtime
	lib.SetInsecureDevMode(clf.InsecureMode)

	// Apply command line --debug flag to override logger severity.
	if clf.Debug {
		// If debug logging is requested and no file configuration exists, set the
		// log level right away. Otherwise allow the command line flag to override
		// logger severity in file configuration.
		log.SetLevel(log.DebugLevel)
		cfg.Log.SetLevel(log.DebugLevel)
	}

	// If FIPS mode is specified, validate Teleport configuration is FedRAMP/FIPS
	// 140-2 compliant.
	if clf.FIPS {
		// Make sure all cryptographic primitives are FIPS compliant.
		err := utils.UintSliceSubset(defaults.FIPSCipherSuites, cfg.CipherSuites)
		if err != nil {
			return trace.BadParameter("non-FIPS compliant TLS cipher suite selected: %v", err)
		}
		err = utils.StringSliceSubset(defaults.FIPSCiphers, cfg.Ciphers)
		if err != nil {
			return trace.BadParameter("non-FIPS compliant SSH cipher selected: %v", err)
		}
		err = utils.StringSliceSubset(defaults.FIPSKEXAlgorithms, cfg.KEXAlgorithms)
		if err != nil {
			return trace.BadParameter("non-FIPS compliant SSH kex algorithm selected: %v", err)
		}
		err = utils.StringSliceSubset(defaults.FIPSMACAlgorithms, cfg.MACAlgorithms)
		if err != nil {
			return trace.BadParameter("non-FIPS compliant SSH mac algorithm selected: %v", err)
		}
	}

	// apply --skip-version-check flag.
	if clf.SkipVersionCheck {
		cfg.SkipVersionCheck = clf.SkipVersionCheck
	}

	// apply --debug flag to config:
	if clf.Debug {
		cfg.Console = io.Discard
		cfg.Debug = clf.Debug
	}

	// apply --roles flag:
	if clf.Roles != "" {
		if err := validateRoles(clf.Roles); err != nil {
			return trace.Wrap(err)
		}
		cfg.SSH.Enabled = strings.Contains(clf.Roles, defaults.RoleNode)
	}

	// apply --auth-server flag:
	if len(clf.AuthServerAddr) > 0 {
		cfg.AuthServers = make([]utils.NetAddr, 0, len(clf.AuthServerAddr))
		for _, as := range clf.AuthServerAddr {
			addr, err := utils.ParseHostPortAddr(as, defaults.AuthListenPort)
			if err != nil {
				return trace.BadParameter("cannot parse auth server address: '%v'", as)
			}
			cfg.AuthServers = append(cfg.AuthServers, *addr)
		}
	}

	// apply --name flag:
	if clf.NodeName != "" {
		cfg.Hostname = clf.NodeName
	}

	// apply --pid-file flag
	if clf.PIDFile != "" {
		cfg.PIDFile = clf.PIDFile
	}

	if clf.AuthToken != "" {
		// store the value of the --token flag:
		cfg.SetToken(clf.AuthToken)
	}

	// Apply flags used for the node to validate the Auth Server.
	if err := cfg.ApplyCAPins(clf.CAPins); err != nil {
		return trace.Wrap(err)
	}

	// apply --listen-ip flag:
	if clf.ListenIP != nil {
		applyListenIP(clf.ListenIP, cfg)
	}

	// --advertise-ip flag
	if clf.AdvertiseIP != "" {
		if _, _, err := utils.ParseAdvertiseAddr(clf.AdvertiseIP); err != nil {
			return trace.Wrap(err)
		}
		cfg.AdvertiseIP = clf.AdvertiseIP
	}

	// apply --labels flag
	if err := parseLabelsApply(clf.Labels, &cfg.SSH); err != nil {
		return trace.Wrap(err)
	}

	// --pid-file:
	if clf.PIDFile != "" {
		cfg.PIDFile = clf.PIDFile
	}

	// command line flag takes precedence over file config
	if clf.PermitUserEnvironment {
		cfg.SSH.PermitUserEnvironment = true
	}

	return nil
}

// parseLabels parses the labels command line flag and returns static and
// dynamic labels.
func parseLabels(spec string) (map[string]string, services.CommandLabels, error) {
	// Base syntax parsing, the spec must be in the form of 'key=value,more="better"'.
	lmap, err := client.ParseLabelSpec(spec)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	static := make(map[string]string)
	dynamic := make(services.CommandLabels)

	if len(lmap) == 0 {
		return static, dynamic, nil
	}

	// Loop over all parsed labels and set either static or dynamic labels.
	for key, value := range lmap {
		dynamicLabel, err := isCmdLabelSpec(value)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		if dynamicLabel != nil {
			dynamic[key] = dynamicLabel
		} else {
			static[key] = value
		}
	}

	return static, dynamic, nil
}

// parseLabelsApply reads in the labels command line flag and tries to
// correctly populate static and dynamic labels for the SSH service.
func parseLabelsApply(spec string, sshConf *service.SSHConfig) error {
	if spec == "" {
		return nil
	}

	var err error
	sshConf.Labels, sshConf.CmdLabels, err = parseLabels(spec)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// isCmdLabelSpec tries to interpret a given string as a "command label" spec.
// A command label spec looks like [time_duration:command param1 param2 ...] where
// time_duration is in "1h2m1s" form.
//
// Example of a valid spec: "[1h:/bin/uname -m]"
func isCmdLabelSpec(spec string) (types.CommandLabel, error) {
	// command spec? (surrounded by brackets?)
	if len(spec) > 5 && spec[0] == '[' && spec[len(spec)-1] == ']' {
		invalidSpecError := trace.BadParameter(
			"invalid command label spec: '%s'", spec)
		spec = strings.Trim(spec, "[]")
		idx := strings.IndexRune(spec, ':')
		if idx < 0 {
			return nil, trace.Wrap(invalidSpecError)
		}
		periodSpec := spec[:idx]
		period, err := time.ParseDuration(periodSpec)
		if err != nil {
			return nil, trace.Wrap(invalidSpecError)
		}
		cmdSpec := spec[idx+1:]
		if len(cmdSpec) < 1 {
			return nil, trace.Wrap(invalidSpecError)
		}
		openQuote := false
		return &types.CommandLabelV2{
			Period: types.NewDuration(period),
			Command: strings.FieldsFunc(cmdSpec, func(c rune) bool {
				if c == '"' {
					openQuote = !openQuote
				}
				return unicode.IsSpace(c) && !openQuote
			}),
		}, nil
	}
	// not a valid spec
	return nil, nil
}

// applyListenIP replaces all 'listen addr' settings for all services with
// a given IP
func applyListenIP(ip net.IP, cfg *service.Config) {
	listeningAddresses := []*utils.NetAddr{
		&cfg.SSH.Addr,
	}
	for _, addr := range listeningAddresses {
		replaceHost(addr, ip.String())
	}
}

// replaceHost takes utils.NetAddr and replaces the hostname in it, preserving
// the original port
func replaceHost(addr *utils.NetAddr, newHost string) {
	_, port, err := net.SplitHostPort(addr.Addr)
	if err != nil {
		log.Errorf("failed parsing address: '%v'", addr.Addr)
	}
	addr.Addr = net.JoinHostPort(newHost, port)
}

// validateRoles makes sure that value passed to the --roles flag is valid
func validateRoles(roles string) error {
	for _, role := range splitRoles(roles) {
		switch role {
		case defaults.RoleNode:
		default:
			return trace.Errorf("unknown role: '%s'", role)
		}
	}
	return nil
}

// splitRoles splits in the format roles expects.
func splitRoles(roles string) []string {
	return strings.Split(roles, ",")
}
