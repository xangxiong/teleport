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
	"crypto/x509"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/pam"
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

// applySSHConfig applies file configuration for the "ssh_service" section.
func applySSHConfig(fc *FileConfig, cfg *service.Config) (err error) {
	if fc.SSH.ListenAddress != "" {
		addr, err := utils.ParseHostPortAddr(fc.SSH.ListenAddress, int(defaults.SSHServerListenPort))
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.SSH.Addr = *addr
	}
	if fc.SSH.Labels != nil {
		cfg.SSH.Labels = make(map[string]string)
		for k, v := range fc.SSH.Labels {
			cfg.SSH.Labels[k] = v
		}
	}
	if fc.SSH.Commands != nil {
		cfg.SSH.CmdLabels = make(services.CommandLabels)
		for _, cmdLabel := range fc.SSH.Commands {
			cfg.SSH.CmdLabels[cmdLabel.Name] = &types.CommandLabelV2{
				Period:  types.NewDuration(cmdLabel.Period),
				Command: cmdLabel.Command,
				Result:  "",
			}
		}
	}
	if fc.SSH.Namespace != "" {
		cfg.SSH.Namespace = fc.SSH.Namespace
	}
	if fc.SSH.PermitUserEnvironment {
		cfg.SSH.PermitUserEnvironment = true
	}
	if fc.SSH.DisableCreateHostUser || runtime.GOOS != constants.LinuxOS {
		cfg.SSH.DisableCreateHostUser = true
		if runtime.GOOS != constants.LinuxOS {
			log.Debugln("Disabling host user creation as this feature is only available on Linux")
		}
	}
	if fc.SSH.PAM != nil {
		cfg.SSH.PAM = fc.SSH.PAM.Parse()

		// If PAM is enabled, make sure that Teleport was built with PAM support
		// and the PAM library was found at runtime.
		if cfg.SSH.PAM.Enabled {
			if !pam.BuildHasPAM() {
				errorMessage := "Unable to start Teleport: PAM was enabled in file configuration but this \n" +
					"Teleport binary was built without PAM support. To continue either download a \n" +
					"Teleport binary build with PAM support from https://goteleport.com/teleport \n" +
					"or disable PAM in file configuration."
				return trace.BadParameter(errorMessage)
			}
			if !pam.SystemHasPAM() {
				errorMessage := "Unable to start Teleport: PAM was enabled in file configuration but this \n" +
					"system does not have the needed PAM library installed. To continue either \n" +
					"install libpam or disable PAM in file configuration."
				return trace.BadParameter(errorMessage)
			}
		}
	}
	if len(fc.SSH.PublicAddr) != 0 {
		addrs, err := utils.AddrsFromStrings(fc.SSH.PublicAddr, defaults.SSHServerListenPort)
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.SSH.PublicAddrs = addrs
	}
	if fc.SSH.BPF != nil {
		cfg.SSH.BPF = fc.SSH.BPF.Parse()
	}
	if fc.SSH.RestrictedSession != nil {
		rs, err := fc.SSH.RestrictedSession.Parse()
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.SSH.RestrictedSession = rs
	}

	cfg.SSH.AllowTCPForwarding = fc.SSH.AllowTCPForwarding()

	cfg.SSH.X11, err = fc.SSH.X11ServerConfig()
	if err != nil {
		return trace.Wrap(err)
	}

	cfg.SSH.AllowFileCopying = fc.SSH.SSHFileCopy()

	return nil
}

// readCACert reads database CA certificate from the config file.
// First 'tls.ca_cert_file` is being read, then deprecated 'ca_cert_file' if
// the first one is not set.
func readCACert(database *Database) ([]byte, error) {
	var (
		caBytes []byte
		err     error
	)
	if database.TLS.CACertFile != "" {
		caBytes, err = os.ReadFile(database.TLS.CACertFile)
		if err != nil {
			return nil, trace.ConvertSystemError(err)
		}
	}

	// ca_cert_file is deprecated, but we still support it.
	// Print a warning if the old field is still being used.
	if database.CACertFile != "" {
		if database.TLS.CACertFile != "" {
			// New and old fields are set. Ignore the old field.
			log.Warnf("Ignoring deprecated ca_cert_file in %s configuration; using tls.ca_cert_file.", database.Name)
		} else {
			// Only old field is set, inform about deprecation.
			log.Warnf("ca_cert_file is deprecated, please use tls.ca_cert_file instead for %s.", database.Name)

			caBytes, err = os.ReadFile(database.CACertFile)
			if err != nil {
				return nil, trace.ConvertSystemError(err)
			}
		}
	}

	return caBytes, nil
}

// applyAppsConfig applies file configuration for the "app_service" section.
func applyAppsConfig(fc *FileConfig, cfg *service.Config) error {
	// Apps are enabled.
	cfg.Apps.Enabled = true

	// Enable debugging application if requested.
	cfg.Apps.DebugApp = fc.Apps.DebugApp

	// Configure resource watcher selectors if present.
	for _, matcher := range fc.Apps.ResourceMatchers {
		cfg.Apps.ResourceMatchers = append(cfg.Apps.ResourceMatchers,
			services.ResourceMatcher{
				Labels: matcher.Labels,
			})
	}

	// Loop over all apps and load app configuration.
	for _, application := range fc.Apps.Apps {
		// Parse the static labels of the application.
		staticLabels := make(map[string]string)
		if application.StaticLabels != nil {
			staticLabels = application.StaticLabels
		}

		// Parse the dynamic labels of the application.
		dynamicLabels := make(services.CommandLabels)
		if application.DynamicLabels != nil {
			for _, v := range application.DynamicLabels {
				dynamicLabels[v.Name] = &types.CommandLabelV2{
					Period:  types.NewDuration(v.Period),
					Command: v.Command,
				}
			}
		}

		// Add the application to the list of proxied applications.
		app := service.App{
			Name:               application.Name,
			Description:        application.Description,
			URI:                application.URI,
			PublicAddr:         application.PublicAddr,
			StaticLabels:       staticLabels,
			DynamicLabels:      dynamicLabels,
			InsecureSkipVerify: application.InsecureSkipVerify,
		}
		if application.Rewrite != nil {
			// Parse http rewrite headers if there are any.
			headers, err := service.ParseHeaders(application.Rewrite.Headers)
			if err != nil {
				return trace.Wrap(err, "failed to parse headers rewrite configuration for app %q",
					application.Name)
			}
			app.Rewrite = &service.Rewrite{
				Redirect: application.Rewrite.Redirect,
				Headers:  headers,
			}
		}
		if application.AWS != nil {
			app.AWS = &service.AppAWS{
				ExternalID: application.AWS.ExternalID,
			}
		}
		if err := app.CheckAndSetDefaults(); err != nil {
			return trace.Wrap(err)
		}
		cfg.Apps.Apps = append(cfg.Apps.Apps, app)
	}

	return nil
}

// applyMetricsConfig applies file configuration for the "metrics_service" section.
func applyMetricsConfig(fc *FileConfig, cfg *service.Config) error {
	// Metrics is enabled.
	cfg.Metrics.Enabled = true

	addr, err := utils.ParseHostPortAddr(fc.Metrics.ListenAddress, int(defaults.MetricsListenPort))
	if err != nil {
		return trace.Wrap(err)
	}
	cfg.Metrics.ListenAddr = addr

	cfg.Metrics.GRPCServerLatency = fc.Metrics.GRPCServerLatency
	cfg.Metrics.GRPCClientLatency = fc.Metrics.GRPCClientLatency

	if !fc.Metrics.MTLSEnabled() {
		return nil
	}

	cfg.Metrics.MTLS = true

	if len(fc.Metrics.KeyPairs) == 0 {
		return trace.BadParameter("at least one keypair shoud be provided when mtls is enabled in the metrics config")
	}

	if len(fc.Metrics.CACerts) == 0 {
		return trace.BadParameter("at least one CA cert shoud be provided when mtls is enabled in the metrics config")
	}

	for _, p := range fc.Metrics.KeyPairs {
		// Check that the certificate exists on disk. This exists to provide the
		// user a sensible error message.
		if !utils.FileExists(p.PrivateKey) {
			return trace.NotFound("metrics service private key does not exist: %s", p.PrivateKey)
		}
		if !utils.FileExists(p.Certificate) {
			return trace.NotFound("metrics service cert does not exist: %s", p.Certificate)
		}

		certificateChainBytes, err := utils.ReadPath(p.Certificate)
		if err != nil {
			return trace.Wrap(err)
		}
		certificateChain, err := utils.ReadCertificateChain(certificateChainBytes)
		if err != nil {
			return trace.Wrap(err)
		}

		if !utils.IsSelfSigned(certificateChain) {
			if err := utils.VerifyCertificateChain(certificateChain); err != nil {
				return trace.BadParameter("unable to verify the metrics service certificate chain in %v: %s",
					p.Certificate, utils.UserMessageFromError(err))
			}
		}

		cfg.Metrics.KeyPairs = append(cfg.Metrics.KeyPairs, service.KeyPairPath{
			PrivateKey:  p.PrivateKey,
			Certificate: p.Certificate,
		})
	}

	for _, caCert := range fc.Metrics.CACerts {
		// Check that the certificate exists on disk. This exists to provide the
		// user a sensible error message.
		if !utils.FileExists(caCert) {
			return trace.NotFound("metrics service ca cert does not exist: %s", caCert)
		}

		cfg.Metrics.CACerts = append(cfg.Metrics.CACerts, caCert)
	}

	return nil
}

// applyWindowsDesktopConfig applies file configuration for the "windows_desktop_service" section.
func applyWindowsDesktopConfig(fc *FileConfig, cfg *service.Config) error {
	cfg.WindowsDesktop.Enabled = true

	if fc.WindowsDesktop.ListenAddress != "" {
		listenAddr, err := utils.ParseHostPortAddr(fc.WindowsDesktop.ListenAddress, int(defaults.WindowsDesktopListenPort))
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.WindowsDesktop.ListenAddr = *listenAddr
	}

	for _, filter := range fc.WindowsDesktop.Discovery.Filters {
		if _, err := ldap.CompileFilter(filter); err != nil {
			return trace.BadParameter("WindowsDesktopService specifies invalid LDAP filter %q", filter)
		}
	}

	for _, attributeName := range fc.WindowsDesktop.Discovery.LabelAttributes {
		if !types.IsValidLabelKey(attributeName) {
			return trace.BadParameter("WindowsDesktopService specifies label_attribute %q which is not a valid label key", attributeName)
		}
	}

	cfg.WindowsDesktop.Discovery = fc.WindowsDesktop.Discovery

	var err error
	cfg.WindowsDesktop.PublicAddrs, err = utils.AddrsFromStrings(fc.WindowsDesktop.PublicAddr, defaults.WindowsDesktopListenPort)
	if err != nil {
		return trace.Wrap(err)
	}
	cfg.WindowsDesktop.Hosts, err = utils.AddrsFromStrings(fc.WindowsDesktop.Hosts, defaults.RDPListenPort)
	if err != nil {
		return trace.Wrap(err)
	}

	var cert *x509.Certificate
	if fc.WindowsDesktop.LDAP.DEREncodedCAFile != "" {
		rawCert, err := os.ReadFile(fc.WindowsDesktop.LDAP.DEREncodedCAFile)
		if err != nil {
			return trace.WrapWithMessage(err, "loading the LDAP CA from file %v", fc.WindowsDesktop.LDAP.DEREncodedCAFile)
		}

		cert, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return trace.WrapWithMessage(err, "parsing the LDAP root CA file %v", fc.WindowsDesktop.LDAP.DEREncodedCAFile)
		}
	}

	cfg.WindowsDesktop.LDAP = service.LDAPConfig{
		Addr:               fc.WindowsDesktop.LDAP.Addr,
		Username:           fc.WindowsDesktop.LDAP.Username,
		Domain:             fc.WindowsDesktop.LDAP.Domain,
		InsecureSkipVerify: fc.WindowsDesktop.LDAP.InsecureSkipVerify,
		CA:                 cert,
	}

	for _, rule := range fc.WindowsDesktop.HostLabels {
		r, err := regexp.Compile(rule.Match)
		if err != nil {
			return trace.BadParameter("WindowsDesktopService specifies invalid regexp %q", rule.Match)
		}

		if len(rule.Labels) == 0 {
			return trace.BadParameter("WindowsDesktopService host regex %q has no labels", rule.Match)
		}

		for k := range rule.Labels {
			if !types.IsValidLabelKey(k) {
				return trace.BadParameter("WindowsDesktopService specifies invalid label %q", k)
			}
		}

		cfg.WindowsDesktop.HostLabels = append(cfg.WindowsDesktop.HostLabels, service.HostLabelRule{
			Regexp: r,
			Labels: rule.Labels,
		})
	}

	return nil
}

// applyTracingConfig applies file configuration for the "tracing_service" section.
func applyTracingConfig(fc *FileConfig, cfg *service.Config) error {
	// Tracing is enabled.
	cfg.Tracing.Enabled = true

	if fc.Tracing.ExporterURL == "" {
		return trace.BadParameter("tracing_service is enabled but no exporter_url is specified")
	}

	cfg.Tracing.ExporterURL = fc.Tracing.ExporterURL
	cfg.Tracing.SamplingRate = float64(fc.Tracing.SamplingRatePerMillion) / 1_000_000.0

	for _, p := range fc.Tracing.KeyPairs {
		// Check that the certificate exists on disk. This exists to provide the
		// user a sensible error message.
		if !utils.FileExists(p.PrivateKey) {
			return trace.NotFound("tracing_service private key does not exist: %s", p.PrivateKey)
		}
		if !utils.FileExists(p.Certificate) {
			return trace.NotFound("tracing_service cert does not exist: %s", p.Certificate)
		}

		cfg.Tracing.KeyPairs = append(cfg.Tracing.KeyPairs, service.KeyPairPath{
			PrivateKey:  p.PrivateKey,
			Certificate: p.Certificate,
		})
	}

	for _, caCert := range fc.Tracing.CACerts {
		// Check that the certificate exists on disk. This exists to provide the
		// user a sensible error message.
		if !utils.FileExists(caCert) {
			return trace.NotFound("tracing_service ca cert does not exist: %s", caCert)
		}

		cfg.Tracing.CACerts = append(cfg.Tracing.CACerts, caCert)
	}

	return nil
}

// applyString takes 'src' and overwrites target with it, unless 'src' is empty
// returns 'True' if 'src' was not empty
func applyString(src string, target *string) bool {
	if src != "" {
		*target = src
		return true
	}
	return false
}

// applyConfigVersion applies config version from parsed file. If config version is not
// present the v1 version will be used as default.
func applyConfigVersion(fc *FileConfig, cfg *service.Config) {
	cfg.Version = defaults.TeleportConfigVersionV1
	if fc.Version != "" {
		cfg.Version = fc.Version
	}
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

		// Make sure cluster settings are also FedRAMP/FIPS 140-2 compliant.
		if cfg.Auth.Enabled {
			// Only SSO based authentication is supported. The SSO provider is where
			// any FedRAMP/FIPS 140-2 compliance (like password complexity) should be
			// enforced.
			if cfg.Auth.Preference.GetAllowLocalAuth() {
				return trace.BadParameter("non-FIPS compliant authentication setting: \"local_auth\" must be false")
			}

			// If sessions are being recorded at the proxy host key checking must be
			// enabled. This make sure the host certificate key algorithm is FIPS
			// compliant.
			if services.IsRecordAtProxy(cfg.Auth.SessionRecordingConfig.GetMode()) &&
				!cfg.Auth.SessionRecordingConfig.GetProxyChecksHostKeys() {
				return trace.BadParameter("non-FIPS compliant proxy settings: \"proxy_checks_host_keys\" must be true")
			}
		}
	}

	// apply --skip-version-check flag.
	if clf.SkipVersionCheck {
		cfg.SkipVersionCheck = clf.SkipVersionCheck
	}

	// apply --insecure-no-tls flag:
	if clf.DisableTLS {
		cfg.Proxy.DisableTLS = clf.DisableTLS
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
		cfg.Auth.Enabled = strings.Contains(clf.Roles, defaults.RoleAuthService)
		cfg.Proxy.Enabled = strings.Contains(clf.Roles, defaults.RoleProxy)
		cfg.Apps.Enabled = strings.Contains(clf.Roles, defaults.RoleApp)
		cfg.Databases.Enabled = strings.Contains(clf.Roles, defaults.RoleDatabase)
	}

	// apply --auth-server flag:
	if len(clf.AuthServerAddr) > 0 {
		if cfg.Auth.Enabled {
			log.Warnf("not starting the local auth service. --auth-server flag tells to connect to another auth server")
			cfg.Auth.Enabled = false
		}
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

	// auth_servers not configured, but the 'auth' is enabled (auth is on localhost)?
	if len(cfg.AuthServers) == 0 && cfg.Auth.Enabled {
		cfg.AuthServers = append(cfg.AuthServers, cfg.Auth.SSHAddr)
	}

	// add data_dir to the backend config:
	if cfg.Auth.StorageConfig.Params == nil {
		cfg.Auth.StorageConfig.Params = backend.Params{}
	}
	cfg.Auth.StorageConfig.Params["data_dir"] = cfg.DataDir
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
		&cfg.Auth.SSHAddr,
		&cfg.Auth.SSHAddr,
		&cfg.Proxy.SSHAddr,
		&cfg.Proxy.WebAddr,
		&cfg.SSH.Addr,
		&cfg.Proxy.ReverseTunnelListenAddr,
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
		case defaults.RoleAuthService,
			defaults.RoleNode,
			defaults.RoleProxy,
			defaults.RoleApp,
			defaults.RoleDatabase,
			defaults.RoleWindowsDesktop:
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

// applyTokenConfig applies the auth_token and join_params to the config
func applyTokenConfig(fc *FileConfig, cfg *service.Config) error {
	if fc.AuthToken != "" {
		cfg.JoinMethod = types.JoinMethodToken
		cfg.SetToken(fc.AuthToken)
	}

	if fc.JoinParams != (JoinParams{}) {
		if cfg.HasToken() {
			return trace.BadParameter("only one of auth_token or join_params should be set")
		}

		cfg.SetToken(fc.JoinParams.TokenName)

		switch fc.JoinParams.Method {
		case types.JoinMethodEC2, types.JoinMethodIAM, types.JoinMethodToken:
			cfg.JoinMethod = fc.JoinParams.Method
		default:
			return trace.BadParameter(`unknown value for join_params.method: %q, expected one of %v`, fc.JoinParams.Method, []types.JoinMethod{types.JoinMethodEC2, types.JoinMethodIAM, types.JoinMethodToken})
		}
	}

	return nil
}
