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
	"io"
	"os"
	"strings"
	"time"

	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/bpf"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/pam"
	"github.com/gravitational/teleport/lib/plugin"
	restricted "github.com/gravitational/teleport/lib/restrictedsession"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/sshutils/x11"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/ghodss/yaml"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/crypto/ssh"
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
