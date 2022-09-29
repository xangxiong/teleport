/*
Copyright 2015-2021 Gravitational, Inc.

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

package service

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/bpf"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/observability/tracing"
	"github.com/gravitational/teleport/lib/pam"
	"github.com/gravitational/teleport/lib/plugin"
	restricted "github.com/gravitational/teleport/lib/restrictedsession"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/sshutils/x11"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/ghodss/yaml"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http/httpguts"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Rate describes a rate ratio, i.e. the number of "events" that happen over
// some unit time period
type Rate struct {
	Amount int
	Time   time.Duration
}

// Config structure is used to initialize _all_ services Teleport can run.
// Some settings are global (like DataDir) while others are grouped into
// sections, like AuthConfig
type Config struct {
	// Teleport configuration version.
	Version string
	// DataDir is the directory where teleport stores its permanent state
	// (in case of auth server backed by BoltDB) or local state, e.g. keys
	DataDir string

	// Hostname is a node host name
	Hostname string

	// JoinMethod is the method the instance will use to join the auth server
	JoinMethod types.JoinMethod

	// AuthServers is a list of auth servers, proxies and peer auth servers to
	// connect to. Yes, this is not just auth servers, the field name is
	// misleading.
	AuthServers []utils.NetAddr

	// Identities is an optional list of pre-generated key pairs
	// for teleport roles, this is helpful when server is preconfigured
	Identities []*auth.Identity

	// AdvertiseIP is used to "publish" an alternative IP address or hostname this node
	// can be reached on, if running behind NAT
	AdvertiseIP string

	// CachePolicy sets caching policy for nodes and proxies
	// in case if they lose connection to auth servers
	CachePolicy CachePolicy

	// SSH service configuration. Manages SSH servers running within the cluster.
	SSH SSHConfig

	// Keygen points to a key generator implementation
	Keygen sshca.Authority

	// HostUUID is a unique UUID of this host (it will be known via this UUID within
	// a teleport cluster). It's automatically generated on 1st start
	HostUUID string

	// Console writer to speak to a user
	Console io.Writer

	// ReverseTunnels is a list of reverse tunnels to create on the
	// first cluster start
	ReverseTunnels []types.ReverseTunnel

	// OIDCConnectors is a list of trusted OpenID Connect identity providers
	OIDCConnectors []types.OIDCConnector

	// PidFile is a full path of the PID file for teleport daemon
	PIDFile string

	// Trust is a service that manages users and credentials
	Trust services.Trust

	// Presence service is a discovery and hearbeat tracker
	Presence services.Presence

	// Events is events service
	Events types.Events

	// Provisioner is a service that keeps track of provisioning tokens
	Provisioner services.Provisioner

	// Trust is a service that manages users and credentials
	Identity services.Identity

	// Access is a service that controls access
	Access services.Access

	// ClusterConfiguration is a service that provides cluster configuration
	ClusterConfiguration services.ClusterConfiguration

	// CipherSuites is a list of TLS ciphersuites that Teleport supports. If
	// omitted, a Teleport selected list of defaults will be used.
	CipherSuites []uint16

	// Ciphers is a list of SSH ciphers that the server supports. If omitted,
	// the defaults will be used.
	Ciphers []string

	// KEXAlgorithms is a list of SSH key exchange (KEX) algorithms that the
	// server supports. If omitted, the defaults will be used.
	KEXAlgorithms []string

	// MACAlgorithms is a list of SSH message authentication codes (MAC) that
	// the server supports. If omitted the defaults will be used.
	MACAlgorithms []string

	// DiagnosticAddr is an address for diagnostic and healthz endpoint service
	DiagnosticAddr utils.NetAddr

	// Debug sets debugging mode, results in diagnostic address
	// endpoint extended with additional /debug handlers
	Debug bool

	// UploadEventsC is a channel for upload events
	// used in tests
	UploadEventsC chan events.UploadEvent `json:"-"`

	// FileDescriptors is an optional list of file descriptors for the process
	// to inherit and use for listeners, used for in-process updates.
	FileDescriptors []FileDescriptor

	// PollingPeriod is set to override default internal polling periods
	// of sync agents, used to speed up integration tests.
	PollingPeriod time.Duration

	// ClientTimeout is set to override default client timeouts
	// used by internal clients, used to speed up integration tests.
	ClientTimeout time.Duration

	// ShutdownTimeout is set to override default shutdown timeout.
	ShutdownTimeout time.Duration

	// CAPins are the SKPI hashes of the CAs used to verify the Auth Server.
	CAPins []string

	// Clock is used to control time in tests.
	Clock clockwork.Clock

	// TeleportVersion is used to control the Teleport version in tests.
	TeleportVersion string

	// FIPS means FedRAMP/FIPS 140-2 compliant configuration was requested.
	FIPS bool

	// SkipVersionCheck means the version checking between server and client
	// will be skipped.
	SkipVersionCheck bool

	// BPFConfig holds configuration for the BPF service.
	BPFConfig *bpf.Config

	// Log optionally specifies the logger
	Log utils.Logger

	// PluginRegistry allows adding enterprise logic to Teleport services
	PluginRegistry plugin.Registry

	// RotationConnectionInterval is the interval between connection
	// attempts as used by the rotation state service
	RotationConnectionInterval time.Duration

	// RestartThreshold describes the number of connection failures per
	// unit time that the node can sustain before restarting itself, as
	// measured by the rotation state service.
	RestartThreshold Rate

	// MaxRetryPeriod is the maximum period between reconnection attempts to auth
	MaxRetryPeriod time.Duration

	// ConnectFailureC is a channel to notify of failures to connect to auth (used in tests).
	ConnectFailureC chan time.Duration

	// TeleportHome is the path to tsh configuration and data, used
	// for loading profiles when TELEPORT_HOME is set
	TeleportHome string

	// CircuitBreakerConfig configures the auth client circuit breaker.
	CircuitBreakerConfig breaker.Config

	// token is either the token needed to join the auth server, or a path pointing to a file
	// that contains the token
	//
	// This is private to avoid external packages reading the value - the value should be obtained
	// using Token()
	token string
}

// Token returns token needed to join the auth server
//
// If the value stored points to a file, it will attempt to read the token value from the file
// and return an error if it wasn't successful
// If the value stored doesn't point to a file, it'll return the value stored
// If the token hasn't been set, an empty string will be returned
func (cfg *Config) Token() (string, error) {
	token, err := utils.TryReadValueAsFile(cfg.token)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return token, nil
}

// SetToken stores the value for --token or auth_token in the config
//
// This can be either the token or an absolute path to a file containing the token.
func (cfg *Config) SetToken(token string) {
	cfg.token = token
}

// HasToken gives the ability to check if there has been a token value stored
// in the config
func (cfg *Config) HasToken() bool {
	return cfg.token != ""
}

// ApplyCAPins assigns the given CA pin(s), filtering out empty pins.
// If a pin is specified as a path to a file, that file must not be empty.
func (cfg *Config) ApplyCAPins(caPins []string) error {
	var filteredPins []string
	for _, pinOrPath := range caPins {
		if pinOrPath == "" {
			continue
		}
		pins, err := utils.TryReadValueAsFile(pinOrPath)
		if err != nil {
			return trace.Wrap(err)
		}
		// an empty pin file is less obvious than a blank ca_pin in the config yaml.
		if pins == "" {
			return trace.BadParameter("empty ca_pin file: %v", pinOrPath)
		}
		filteredPins = append(filteredPins, strings.Split(pins, "\n")...)
	}
	if len(filteredPins) > 0 {
		cfg.CAPins = filteredPins
	}
	return nil
}

// RoleConfig is a config for particular Teleport role
func (cfg *Config) RoleConfig() RoleConfig {
	return RoleConfig{
		DataDir:     cfg.DataDir,
		HostUUID:    cfg.HostUUID,
		HostName:    cfg.Hostname,
		AuthServers: cfg.AuthServers,
		Console:     cfg.Console,
	}
}

// DebugDumpToYAML is useful for debugging: it dumps the Config structure into
// a string
func (cfg *Config) DebugDumpToYAML() string {
	shallow := *cfg
	// do not copy sensitive data to stdout
	shallow.Identities = nil
	out, err := yaml.Marshal(shallow)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

// CachePolicy sets caching policy for proxies and nodes
type CachePolicy struct {
	// Enabled enables or disables caching
	Enabled bool
}

// CheckAndSetDefaults checks and sets default values
func (c *CachePolicy) CheckAndSetDefaults() error {
	return nil
}

// String returns human-friendly representation of the policy
func (c CachePolicy) String() string {
	if !c.Enabled {
		return "no cache"
	}
	return "in-memory cache"
}

// ACME configures ACME automatic certificate renewal
type ACME struct {
	// Enabled enables or disables ACME support
	Enabled bool
	// Email receives notifications from ACME server
	Email string
	// URI is ACME server URI
	URI string
}

// KeyPairPath are paths to a key and certificate file.
type KeyPairPath struct {
	// PrivateKey is the path to a PEM encoded private key.
	PrivateKey string
	// Certificate is the path to a PEM encoded certificate.
	Certificate string
}

// SSHConfig configures SSH server node role
type SSHConfig struct {
	Enabled               bool
	Addr                  utils.NetAddr
	Namespace             string
	Shell                 string
	Limiter               limiter.Config
	Labels                map[string]string
	CmdLabels             services.CommandLabels
	PermitUserEnvironment bool

	// PAM holds PAM configuration for Teleport.
	PAM *pam.Config

	// PublicAddrs affects the SSH host principals and DNS names added to the SSH and TLS certs.
	PublicAddrs []utils.NetAddr

	// BPF holds BPF configuration for Teleport.
	BPF *bpf.Config

	// RestrictedSession holds kernel objects restrictions for Teleport.
	RestrictedSession *restricted.Config

	// AllowTCPForwarding indicates that TCP port forwarding is allowed on this node
	AllowTCPForwarding bool

	// IdleTimeoutMessage is sent to the client when a session expires due to
	// the inactivity timeout expiring. The empty string indicates that no
	// timeout message will be sent.
	IdleTimeoutMessage string

	// X11 holds x11 forwarding configuration for Teleport.
	X11 *x11.ServerConfig

	// AllowFileCopying indicates whether this node is allowed to handle
	// remote file operations via SCP or SFTP.
	AllowFileCopying bool

	// DisableCreateHostUser disables automatic user provisioning on this
	// SSH node.
	DisableCreateHostUser bool
}

// TLSMode defines all possible database verification modes.
type TLSMode string

const (
	// VerifyFull is the strictest. Verifies certificate and server name.
	VerifyFull TLSMode = "verify-full"
	// VerifyCA checks the certificate, but skips the server name verification.
	VerifyCA TLSMode = "verify-ca"
	// Insecure accepts any certificate.
	Insecure TLSMode = "insecure"
)

// AllTLSModes keeps all possible database TLS modes for easy access.
var AllTLSModes = []TLSMode{VerifyFull, VerifyCA, Insecure}

// CheckAndSetDefaults check if TLSMode holds a correct value. If the value is not set
// VerifyFull is set as a default. BadParameter error is returned if value set is incorrect.
func (m *TLSMode) CheckAndSetDefaults() error {
	switch *m {
	case "": // Use VerifyFull if not set.
		*m = VerifyFull
	case VerifyFull, VerifyCA, Insecure:
		// Correct value, do nothing.
	default:
		return trace.BadParameter("provided incorrect TLSMode value. Correct values are: %v", AllTLSModes)
	}

	return nil
}

// ToProto returns a matching protobuf type or VerifyFull for empty value.
func (m TLSMode) ToProto() types.DatabaseTLSMode {
	switch m {
	case VerifyCA:
		return types.DatabaseTLSMode_VERIFY_CA
	case Insecure:
		return types.DatabaseTLSMode_INSECURE
	default: // VerifyFull
		return types.DatabaseTLSMode_VERIFY_FULL
	}
}

// AppsConfig configures application proxy service.
type AppsConfig struct {
	// Enabled enables application proxying service.
	Enabled bool

	// DebugApp enabled a header dumping debugging application.
	DebugApp bool

	// Apps is the list of applications that are being proxied.
	Apps []App

	// ResourceMatchers match cluster database resources.
	ResourceMatchers []services.ResourceMatcher
}

// App is the specific application that will be proxied by the application
// service. This needs to exist because if the "config" package tries to
// directly create a services.App it will get into circular imports.
type App struct {
	// Name of the application.
	Name string

	// Description is the app description.
	Description string

	// URI is the internal address of the application.
	URI string

	// Public address of the application. This is the address users will access
	// the application at.
	PublicAddr string

	// StaticLabels is a map of static labels to apply to this application.
	StaticLabels map[string]string

	// DynamicLabels is a list of dynamic labels to apply to this application.
	DynamicLabels services.CommandLabels

	// InsecureSkipVerify is used to skip validating the server's certificate.
	InsecureSkipVerify bool

	// Rewrite defines a block that is used to rewrite requests and responses.
	Rewrite *Rewrite

	// AWS contains additional options for AWS applications.
	AWS *AppAWS `yaml:"aws,omitempty"`
}

// CheckAndSetDefaults validates an application.
func (a *App) CheckAndSetDefaults() error {
	if a.Name == "" {
		return trace.BadParameter("missing application name")
	}
	if a.URI == "" {
		return trace.BadParameter("missing application %q URI", a.Name)
	}
	// Check if the application name is a valid subdomain. Don't allow names that
	// are invalid subdomains because for trusted clusters the name is used to
	// construct the domain that the application will be available at.
	if errs := validation.IsDNS1035Label(a.Name); len(errs) > 0 {
		return trace.BadParameter("application name %q must be a valid DNS subdomain: https://goteleport.com/teleport/docs/application-access/#application-name", a.Name)
	}
	// Parse and validate URL.
	if _, err := url.Parse(a.URI); err != nil {
		return trace.BadParameter("application %q URI invalid: %v", a.Name, err)
	}
	// If a port was specified or an IP address was provided for the public
	// address, return an error.
	if a.PublicAddr != "" {
		if _, _, err := net.SplitHostPort(a.PublicAddr); err == nil {
			return trace.BadParameter("application %q public_addr %q can not contain a port, applications will be available on the same port as the web proxy", a.Name, a.PublicAddr)
		}
		if net.ParseIP(a.PublicAddr) != nil {
			return trace.BadParameter("application %q public_addr %q can not be an IP address, Teleport Application Access uses DNS names for routing", a.Name, a.PublicAddr)
		}
	}
	// Mark the app as coming from the static configuration.
	if a.StaticLabels == nil {
		a.StaticLabels = make(map[string]string)
	}
	a.StaticLabels[types.OriginLabel] = types.OriginConfigFile
	// Make sure there are no reserved headers in the rewrite configuration.
	// They wouldn't be rewritten even if we allowed them here but catch it
	// early and let the user know.
	if a.Rewrite != nil {
		for _, h := range a.Rewrite.Headers {
			if common.IsReservedHeader(h.Name) {
				return trace.BadParameter("invalid application %q header rewrite configuration: header %q is reserved and can't be rewritten",
					a.Name, http.CanonicalHeaderKey(h.Name))
			}
		}
	}
	return nil
}

// MetricsConfig specifies configuration for the metrics service
type MetricsConfig struct {
	// Enabled turns the metrics service role on or off for this process
	Enabled bool

	// ListenAddr is the address to listen on for incoming metrics requests.
	// Optional.
	ListenAddr *utils.NetAddr

	// MTLS turns mTLS on the metrics service on or off
	MTLS bool

	// KeyPairs are the key and certificate pairs that the metrics service will
	// use for mTLS.
	// Used in conjunction with MTLS = true
	KeyPairs []KeyPairPath

	// CACerts are prometheus ca certs
	// use for mTLS.
	// Used in conjunction with MTLS = true
	CACerts []string

	// GRPCServerLatency enables histogram metrics for each grpc endpoint on the auth server
	GRPCServerLatency bool

	// GRPCServerLatency enables histogram metrics for each grpc endpoint on the auth server
	GRPCClientLatency bool
}

// TracingConfig specifies the configuration for the tracing service
type TracingConfig struct {
	// Enabled turns the tracing service role on or off for this process.
	Enabled bool

	// ExporterURL is the OTLP exporter URL to send spans to.
	ExporterURL string

	// KeyPairs are the paths for key and certificate pairs that the tracing
	// service will use for outbound TLS connections.
	KeyPairs []KeyPairPath

	// CACerts are the paths to the CA certs used to validate the collector.
	CACerts []string

	// SamplingRate is the sampling rate for the exporter.
	// 1.0 will record and export all spans and 0.0 won't record any spans.
	SamplingRate float64
}

// Config generates a tracing.Config that is populated from the values
// provided to the tracing_service
func (t TracingConfig) Config(attrs ...attribute.KeyValue) (*tracing.Config, error) {
	traceConf := &tracing.Config{
		Service:      teleport.ComponentTeleport,
		Attributes:   attrs,
		ExporterURL:  t.ExporterURL,
		SamplingRate: t.SamplingRate,
	}

	tlsConfig := &tls.Config{}
	// if a custom CA is specified, use a custom cert pool
	if len(t.CACerts) > 0 {
		pool := x509.NewCertPool()
		for _, caCertPath := range t.CACerts {
			caCert, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, trace.Wrap(err, "failed to read tracing CA certificate %+v", caCertPath)
			}

			if !pool.AppendCertsFromPEM(caCert) {
				return nil, trace.BadParameter("failed to parse tracing CA certificate: %+v", caCertPath)
			}
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.RootCAs = pool
	}

	// add any custom certificates for mTLS
	if len(t.KeyPairs) > 0 {
		for _, pair := range t.KeyPairs {
			certificate, err := tls.LoadX509KeyPair(pair.Certificate, pair.PrivateKey)
			if err != nil {
				return nil, trace.Wrap(err, "failed to read keypair: %+v", err)
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
		}
	}

	if len(t.CACerts) > 0 || len(t.KeyPairs) > 0 {
		traceConf.TLSConfig = tlsConfig
	}
	return traceConf, nil
}

// WindowsDesktopConfig specifies the configuration for the Windows Desktop
// Access service.
type WindowsDesktopConfig struct {
	Enabled bool
	// ListenAddr is the address to listed on for incoming desktop connections.
	ListenAddr utils.NetAddr
	// PublicAddrs is a list of advertised public addresses of the service.
	PublicAddrs []utils.NetAddr
	// LDAP is the LDAP connection parameters.
	LDAP LDAPConfig

	// Discovery configures automatic desktop discovery via LDAP.
	Discovery LDAPDiscoveryConfig

	// Hosts is an optional list of static Windows hosts to expose through this
	// service.
	Hosts []utils.NetAddr
	// ConnLimiter limits the connection and request rates.
	ConnLimiter limiter.Config
	// HostLabels specifies rules that are used to apply labels to Windows hosts.
	HostLabels HostLabelRules
}

type LDAPDiscoveryConfig struct {
	// BaseDN is the base DN to search for desktops.
	// Use the value '*' to search from the root of the domain,
	// or leave blank to disable desktop discovery.
	BaseDN string `yaml:"base_dn"`
	// Filters are additional LDAP filters to apply to the search.
	// See: https://ldap.com/ldap-filters/
	Filters []string `yaml:"filters"`
	// LabelAttributes are LDAP attributes to apply to hosts discovered
	// via LDAP. Teleport labels hosts by prefixing the attribute with
	// "ldap/" - for example, a value of "location" here would result in
	// discovered desktops having a label with key "ldap/location" and
	// the value being the value of the "location" attribute.
	LabelAttributes []string `yaml:"label_attributes"`
}

// HostLabelRules is a collection of rules describing how to apply labels to hosts.
type HostLabelRules []HostLabelRule

// LabelsForHost returns the set of all labels that should be applied
// to the specified host. If multiple rules match and specify the same
// label keys, the value will be that of the last matching rule.
func (h HostLabelRules) LabelsForHost(host string) map[string]string {
	// TODO(zmb3): consider memoizing this call - the set of rules doesn't
	// change, so it may be worth not matching regexps on each heartbeat.
	result := make(map[string]string)
	for _, rule := range h {
		if rule.Regexp.MatchString(host) {
			for k, v := range rule.Labels {
				result[k] = v
			}
		}
	}
	return result
}

// HostLabelRule specifies a set of labels that should be applied to
// hosts matching the provided regexp.
type HostLabelRule struct {
	Regexp *regexp.Regexp
	Labels map[string]string
}

// LDAPConfig is the LDAP connection parameters.
type LDAPConfig struct {
	// Addr is the address:port of the LDAP server (typically port 389).
	Addr string
	// Domain is the ActiveDirectory domain name.
	Domain string
	// Username for LDAP authentication.
	Username string
	// InsecureSkipVerify decides whether whether we skip verifying with the LDAP server's CA when making the LDAPS connection.
	InsecureSkipVerify bool
	// CA is an optional CA cert to be used for verification if InsecureSkipVerify is set to false.
	CA *x509.Certificate
}

// Rewrite is a list of rewriting rules to apply to requests and responses.
type Rewrite struct {
	// Redirect is a list of hosts that should be rewritten to the public address.
	Redirect []string
	// Headers is a list of extra headers to inject in the request.
	Headers []Header
}

// Header represents a single http header passed over to the proxied application.
type Header struct {
	// Name is the http header name.
	Name string
	// Value is the http header value.
	Value string
}

// ParseHeader parses the provided string as a http header.
func ParseHeader(header string) (*Header, error) {
	parts := strings.SplitN(header, ":", 2)
	if len(parts) != 2 {
		return nil, trace.BadParameter("failed to parse %q as http header", header)
	}
	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if !httpguts.ValidHeaderFieldName(name) {
		return nil, trace.BadParameter("invalid http header name: %q", header)
	}
	if !httpguts.ValidHeaderFieldValue(value) {
		return nil, trace.BadParameter("invalid http header value: %q", header)
	}
	return &Header{
		Name:  name,
		Value: value,
	}, nil
}

// ParseHeaders parses the provided list as http headers.
func ParseHeaders(headers []string) (headersOut []Header, err error) {
	for _, header := range headers {
		h, err := ParseHeader(header)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		headersOut = append(headersOut, *h)
	}
	return headersOut, nil
}

// AppAWS contains additional options for AWS applications.
type AppAWS struct {
	// ExternalID is the AWS External ID used when assuming roles in this app.
	ExternalID string `yaml:"external_id,omitempty"`
}

// MakeDefaultConfig creates a new Config structure and populates it with defaults
func MakeDefaultConfig() (config *Config) {
	config = &Config{}
	ApplyDefaults(config)
	return config
}

// ApplyDefaults applies default values to the existing config structure
func ApplyDefaults(cfg *Config) {
	// Get defaults for Cipher, Kex algorithms, and MAC algorithms from
	// golang.org/x/crypto/ssh default config.
	var sc ssh.Config
	sc.SetDefaults()

	if cfg.Log == nil {
		cfg.Log = utils.NewLogger()
	}

	// Remove insecure and (borderline insecure) cryptographic primitives from
	// default configuration. These can still be added back in file configuration by
	// users, but not supported by default by Teleport. See #1856 for more
	// details.
	kex := utils.RemoveFromSlice(sc.KeyExchanges,
		defaults.DiffieHellmanGroup1SHA1,
		defaults.DiffieHellmanGroup14SHA1)
	macs := utils.RemoveFromSlice(sc.MACs,
		defaults.HMACSHA1,
		defaults.HMACSHA196)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
		cfg.Log.Errorf("Failed to determine hostname: %v.", err)
	}

	// Global defaults.
	cfg.Hostname = hostname
	cfg.DataDir = defaults.DataDir
	cfg.Console = os.Stdout
	cfg.CipherSuites = utils.DefaultCipherSuites()
	cfg.Ciphers = sc.Ciphers
	cfg.KEXAlgorithms = kex
	cfg.MACAlgorithms = macs

	// SSH service defaults.
	cfg.SSH.Enabled = true
	cfg.SSH.Shell = defaults.DefaultShell
	defaults.ConfigureLimiter(&cfg.SSH.Limiter)
	cfg.SSH.PAM = &pam.Config{Enabled: false}
	cfg.SSH.BPF = &bpf.Config{Enabled: false}
	cfg.SSH.RestrictedSession = &restricted.Config{Enabled: false}
	cfg.SSH.AllowTCPForwarding = true
	cfg.SSH.AllowFileCopying = true

	cfg.RotationConnectionInterval = defaults.HighResPollingPeriod
	cfg.RestartThreshold = Rate{
		Amount: defaults.MaxConnectionErrorsBeforeRestart,
		Time:   defaults.ConnectionErrorMeasurementPeriod,
	}
	cfg.MaxRetryPeriod = defaults.MaxWatcherBackoff
	cfg.ConnectFailureC = make(chan time.Duration, 1)
	cfg.CircuitBreakerConfig = breaker.DefaultBreakerConfig(cfg.Clock)
}

// ApplyFIPSDefaults updates default configuration to be FedRAMP/FIPS 140-2
// compliant.
func ApplyFIPSDefaults(cfg *Config) {
	cfg.FIPS = true

	// Update TLS and SSH cryptographic primitives.
	cfg.CipherSuites = defaults.FIPSCipherSuites
	cfg.Ciphers = defaults.FIPSCiphers
	cfg.KEXAlgorithms = defaults.FIPSKEXAlgorithms
	cfg.MACAlgorithms = defaults.FIPSMACAlgorithms

}
