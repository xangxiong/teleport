/*
Copyright 2016-2019 Gravitational, Inc.

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

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keypaths"
	"github.com/gravitational/teleport/lib/auth"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
	"github.com/gravitational/teleport/lib/client/terminal"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/shell"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/sshutils/scp"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/agentconn"
	"github.com/gravitational/teleport/lib/utils/prompt"
	"github.com/gravitational/teleport/lib/utils/proxy"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	AddKeysToAgentAuto = "auto"
	AddKeysToAgentNo   = "no"
	AddKeysToAgentYes  = "yes"
	AddKeysToAgentOnly = "only"
)

var AllAddKeysOptions = []string{AddKeysToAgentAuto, AddKeysToAgentNo, AddKeysToAgentYes, AddKeysToAgentOnly}

// ValidateAgentKeyOption validates that a string is a valid option for the AddKeysToAgent parameter.
func ValidateAgentKeyOption(supplied string) error {
	for _, option := range AllAddKeysOptions {
		if supplied == option {
			return nil
		}
	}

	return trace.BadParameter("invalid value %q, must be one of %v", supplied, AllAddKeysOptions)
}

// AgentForwardingMode  describes how the user key agent will be forwarded
// to a remote machine, if at all.
type AgentForwardingMode int

const (
	ForwardAgentNo AgentForwardingMode = iota
	ForwardAgentYes
	ForwardAgentLocal
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentClient,
})

// ForwardedPort specifies local tunnel to remote
// destination managed by the client, is equivalent
// of ssh -L src:host:dst command
type ForwardedPort struct {
	SrcIP    string
	SrcPort  int
	DestPort int
	DestHost string
}

// ForwardedPorts contains an array of forwarded port structs
type ForwardedPorts []ForwardedPort

// ToString returns a string representation of a forwarded port spec, compatible
// with OpenSSH's -L  flag, i.e. "src_host:src_port:dest_host:dest_port".
func (p *ForwardedPort) ToString() string {
	sport := strconv.Itoa(p.SrcPort)
	dport := strconv.Itoa(p.DestPort)
	if utils.IsLocalhost(p.SrcIP) {
		return sport + ":" + net.JoinHostPort(p.DestHost, dport)
	}
	return net.JoinHostPort(p.SrcIP, sport) + ":" + net.JoinHostPort(p.DestHost, dport)
}

// DynamicForwardedPort local port for dynamic application-level port
// forwarding. Whenever a connection is made to this port, SOCKS5 protocol
// is used to determine the address of the remote host. More or less
// equivalent to OpenSSH's -D flag.
type DynamicForwardedPort struct {
	// SrcIP is the IP address to listen on locally.
	SrcIP string

	// SrcPort is the port to listen on locally.
	SrcPort int
}

// DynamicForwardedPorts is a slice of locally forwarded dynamic ports (SOCKS5).
type DynamicForwardedPorts []DynamicForwardedPort

// ToString returns a string representation of a dynamic port spec, compatible
// with OpenSSH's -D flag, i.e. "src_host:src_port".
func (p *DynamicForwardedPort) ToString() string {
	sport := strconv.Itoa(p.SrcPort)
	if utils.IsLocalhost(p.SrcIP) {
		return sport
	}
	return net.JoinHostPort(p.SrcIP, sport)
}

// HostKeyCallback is called by SSH client when it needs to check
// remote host key or certificate validity
type HostKeyCallback func(host string, ip net.Addr, key ssh.PublicKey) error

// Config is a client config
type Config struct {
	// Username is the Teleport account username (for logging into Teleport proxies)
	Username string
	// ExplicitUsername is true if Username was initially set by the end-user
	// (for example, using command-line flags).
	ExplicitUsername bool

	// Remote host to connect
	Host string

	// SearchKeywords host to connect
	SearchKeywords []string

	// PredicateExpression host to connect
	PredicateExpression string

	// Labels represent host Labels
	Labels map[string]string

	// Namespace is nodes namespace
	Namespace string

	// HostLogin is a user login on a remote host
	HostLogin string

	// HostPort is a remote host port to connect to. This is used for **explicit**
	// port setting via -p flag, otherwise '0' is passed which means "use server default"
	HostPort int

	// JumpHosts if specified are interpreted in a similar way
	// as -J flag in ssh - used to dial through
	JumpHosts []utils.JumpHost

	// WebProxyAddr is the host:port the web proxy can be accessed at.
	WebProxyAddr string

	// SSHProxyAddr is the host:port the SSH proxy can be accessed at.
	SSHProxyAddr string

	// KeyTTL is a time to live for the temporary SSH keypair to remain valid:
	KeyTTL time.Duration

	// InsecureSkipVerify is an option to skip HTTPS cert check
	InsecureSkipVerify bool

	// SkipLocalAuth tells the client to use AuthMethods parameter for authentication and NOT
	// use its own SSH agent or ask user for passwords. This is used by external programs linking
	// against Teleport client and obtaining credentials from elsewhere.
	SkipLocalAuth bool

	// UseKeyPrincipals forces the use of the username from the key principals rather than using
	// the current user username.
	UseKeyPrincipals bool

	// Agent is used when SkipLocalAuth is true
	Agent agent.Agent

	// PreloadKey is a key with which to initialize a local in-memory keystore.
	PreloadKey *Key

	// ForwardAgent is used by the client to request agent forwarding from the server.
	ForwardAgent AgentForwardingMode

	// EnableX11Forwarding specifies whether X11 forwarding should be enabled.
	EnableX11Forwarding bool

	// X11ForwardingTimeout can be set to set a X11 forwarding timeout in seconds,
	// after which any X11 forwarding requests in that session will be rejected.
	X11ForwardingTimeout time.Duration

	// X11ForwardingTrusted specifies the X11 forwarding security mode.
	X11ForwardingTrusted bool

	// AuthMethods are used to login into the cluster. If specified, the client will
	// use them in addition to certs stored in its local agent (from disk)
	AuthMethods []ssh.AuthMethod

	// TLSConfig is TLS configuration, if specified, the client
	// will use this TLS configuration to access API endpoints
	TLS *tls.Config

	// DefaultPrincipal determines the default SSH username (principal) the client should be using
	// when connecting to auth/proxy servers. Usually it's returned with a certificate,
	// but this variables provides a default (used by the web-based terminal client)
	DefaultPrincipal string

	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	// ExitStatus carries the returned value (exit status) of the remote
	// process execution (via SSH exec)
	ExitStatus int

	// SiteName specifies site to execute operation,
	// if omitted, first available site will be selected
	SiteName string

	// LocalForwardPorts are the local ports tsh listens on for port forwarding
	// (parameters to -L ssh flag).
	LocalForwardPorts ForwardedPorts

	// DynamicForwardedPorts are the list of ports tsh listens on for dynamic
	// port forwarding (parameters to -D ssh flag).
	DynamicForwardedPorts DynamicForwardedPorts

	// HostKeyCallback will be called to check host keys of the remote
	// node, if not specified will be using CheckHostSignature function
	// that uses local cache to validate hosts
	HostKeyCallback ssh.HostKeyCallback

	// KeyDir defines where temporary session keys will be stored.
	// if empty, they'll go to ~/.tsh
	KeysDir string

	// Env is a map of environmnent variables to send when opening session
	Env map[string]string

	// Interactive, when set to true, tells tsh to launch a remote command
	// in interactive mode, i.e. attaching the temrinal to it
	Interactive bool

	// ClientAddr (if set) specifies the true client IP. Usually it's not needed (since the server
	// can look at the connecting address to determine client's IP) but for cases when the
	// client is web-based, this must be set to HTTP's remote addr
	ClientAddr string

	// CachePolicy defines local caching policy in case if discovery goes down
	// by default does not use caching
	CachePolicy *CachePolicy

	// CertificateFormat is the format of the SSH certificate.
	CertificateFormat string

	// AuthConnector is the name of the authentication connector to use.
	AuthConnector string

	// AuthenticatorAttachment is the desired authenticator attachment.
	AuthenticatorAttachment wancli.AuthenticatorAttachment

	// PreferOTP prefers OTP in favor of other MFA methods.
	// Useful in constrained environments without access to USB or platform
	// authenticators, such as remote hosts or virtual machines.
	PreferOTP bool

	// CheckVersions will check that client version is compatible
	// with auth server version when connecting.
	CheckVersions bool

	// BindAddr is an optional host:port to bind to for SSO redirect flows.
	BindAddr string

	// NoRemoteExec will not execute a remote command after connecting to a host,
	// will block instead. Useful when port forwarding. Equivalent of -N for OpenSSH.
	NoRemoteExec bool

	// Browser can be used to pass the name of a browser to override the system default
	// (not currently implemented), or set to 'none' to suppress browser opening entirely.
	Browser string

	// AddKeysToAgent specifies how the client handles keys.
	//	auto - will attempt to add keys to agent if the agent supports it
	//	only - attempt to load keys into agent but don't write them to disk
	//	on - attempt to load keys into agent
	//	off - do not attempt to load keys into agent
	AddKeysToAgent string

	// EnableEscapeSequences will scan Stdin for SSH escape sequences during
	// command/shell execution. This also requires Stdin to be an interactive
	// terminal.
	EnableEscapeSequences bool

	// MockSSOLogin is used in tests for mocking the SSO login response.
	MockSSOLogin SSOLoginFunc

	// HomePath is where tsh stores profiles
	HomePath string

	// TLSRoutingEnabled indicates that proxy supports ALPN SNI server where
	// all proxy services are exposed on a single TLS listener (Proxy Web Listener).
	TLSRoutingEnabled bool

	// Reason is a reason attached to started sessions meant to describe their intent.
	Reason string

	// Invited is a list of people invited to a session.
	Invited []string

	// DisplayParticipantRequirements is set if debug information about participants requirements
	// should be printed in moderated sessions.
	DisplayParticipantRequirements bool

	// ExtraProxyHeaders is a collection of http headers to be included in requests to the WebProxy.
	ExtraProxyHeaders map[string]string

	// AllowStdinHijack allows stdin hijack during MFA prompts.
	// Stdin hijack provides a better login UX, but it can be difficult to reason
	// about and is often a source of bugs.
	// Do not set this options unless you deeply understand what you are doing.
	AllowStdinHijack bool
}

// CachePolicy defines cache policy for local clients
type CachePolicy struct {
	// CacheTTL defines cache TTL
	CacheTTL time.Duration
	// NeverExpire never expires local cache information
	NeverExpires bool
}

// MakeDefaultConfig returns default client config
func MakeDefaultConfig() *Config {
	return &Config{
		Stdout:                os.Stdout,
		Stderr:                os.Stderr,
		Stdin:                 os.Stdin,
		AddKeysToAgent:        AddKeysToAgentAuto,
		EnableEscapeSequences: true,
	}
}

// VirtualPathKind is the suffix component for env vars denoting the type of
// file that will be loaded.
type VirtualPathKind string

const (
	// VirtualPathEnvPrefix is the env var name prefix shared by all virtual
	// path vars.
	VirtualPathEnvPrefix = "TSH_VIRTUAL_PATH"

	VirtualPathKey        VirtualPathKind = "KEY"
	VirtualPathCA         VirtualPathKind = "CA"
	VirtualPathDatabase   VirtualPathKind = "DB"
	VirtualPathApp        VirtualPathKind = "APP"
	VirtualPathKubernetes VirtualPathKind = "KUBE"
)

// VirtualPathParams are an ordered list of additional optional parameters
// for a virtual path. They can be used to specify a more exact resource name
// if multiple might be available. Simpler integrations can instead only
// specify the kind and it will apply wherever a more specific env var isn't
// found.
type VirtualPathParams []string

// VirtualPathCAParams returns parameters for selecting CA certificates.
func VirtualPathCAParams(caType types.CertAuthType) VirtualPathParams {
	return VirtualPathParams{
		strings.ToUpper(string(caType)),
	}
}

// VirtualPathDatabaseParams returns parameters for selecting specific database
// certificates.
func VirtualPathDatabaseParams(databaseName string) VirtualPathParams {
	return VirtualPathParams{databaseName}
}

// VirtualPathAppParams returns parameters for selecting specific apps by name.
func VirtualPathAppParams(appName string) VirtualPathParams {
	return VirtualPathParams{appName}
}

// VirtualPathKubernetesParams returns parameters for selecting k8s clusters by
// name.
func VirtualPathKubernetesParams(k8sCluster string) VirtualPathParams {
	return VirtualPathParams{k8sCluster}
}

// VirtualPathEnvName formats a single virtual path environment variable name.
func VirtualPathEnvName(kind VirtualPathKind, params VirtualPathParams) string {
	components := append([]string{
		VirtualPathEnvPrefix,
		string(kind),
	}, params...)

	return strings.ToUpper(strings.Join(components, "_"))
}

// VirtualPathEnvNames determines an ordered list of environment variables that
// should be checked to resolve an env var override. Params may be nil to
// indicate no additional arguments are to be specified or accepted.
func VirtualPathEnvNames(kind VirtualPathKind, params VirtualPathParams) []string {
	// Bail out early if there are no parameters.
	if len(params) == 0 {
		return []string{VirtualPathEnvName(kind, VirtualPathParams{})}
	}

	var vars []string
	for i := len(params); i >= 0; i-- {
		vars = append(vars, VirtualPathEnvName(kind, params[0:i]))
	}

	return vars
}

// ProfileStatus combines metadata from the logged in profile and associated
// SSH certificate.
type ProfileStatus struct {
	// Name is the profile name.
	Name string

	// Dir is the directory where profile is located.
	Dir string

	// ProxyURL is the URL the web client is accessible at.
	ProxyURL url.URL

	// Username is the Teleport username.
	Username string

	// Roles is a list of Teleport Roles this user has been assigned.
	Roles []string

	// Logins are the Linux accounts, also known as principals in OpenSSH terminology.
	Logins []string

	// Apps is a list of apps this profile is logged into.
	Apps []tlsca.RouteToApp

	// ValidUntil is the time at which this SSH certificate will expire.
	ValidUntil time.Time

	// Extensions is a list of enabled SSH features for the certificate.
	Extensions []string

	// CriticalOptions is a map of SSH critical options for the certificate.
	CriticalOptions map[string]string

	// Cluster is a selected cluster
	Cluster string

	// Traits hold claim data used to populate a role at runtime.
	Traits wrappers.Traits

	// ActiveRequests tracks the privilege escalation requests applied
	// during certificate construction.
	ActiveRequests services.RequestIDs

	// AWSRoleARNs is a list of allowed AWS role ARNs user can assume.
	AWSRolesARNs []string

	// AllowedResourceIDs is a list of resources the user can access. An empty
	// list means there are no resource-specific restrictions.
	AllowedResourceIDs []types.ResourceID

	// IsVirtual is set when this profile does not actually exist on disk,
	// probably because it was constructed from an identity file. When set,
	// certain profile functions - particularly those that return paths to
	// files on disk - must be accompanied by fallback logic when those paths
	// do not exist.
	IsVirtual bool
}

// IsExpired returns true if profile is not expired yet
func (p *ProfileStatus) IsExpired(clock clockwork.Clock) bool {
	return p.ValidUntil.Sub(clock.Now()) <= 0
}

// virtualPathWarnOnce is used to ensure warnings about missing virtual path
// environment variables are consolidated into a single message and not spammed
// to the console.
var virtualPathWarnOnce sync.Once

// virtualPathFromEnv attempts to retrieve the path as defined by the given
// formatter from the environment.
func (p *ProfileStatus) virtualPathFromEnv(kind VirtualPathKind, params VirtualPathParams) (string, bool) {
	if !p.IsVirtual {
		return "", false
	}

	for _, envName := range VirtualPathEnvNames(kind, params) {
		if val, ok := os.LookupEnv(envName); ok {
			return val, true
		}
	}

	// If we can't resolve any env vars, this will return garbage which we
	// should at least warn about. As ugly as this is, arguably making every
	// profile path lookup fallible is even uglier.
	log.Debugf("Could not resolve path to virtual profile entry of type %s "+
		"with parameters %+v.", kind, params)

	virtualPathWarnOnce.Do(func() {
		log.Errorf("A virtual profile is in use due to an identity file " +
			"(`-i ...`) but this functionality requires additional files on " +
			"disk and may fail. Consider using a compatible wrapper " +
			"application (e.g. Machine ID) for this command.")
	})

	return "", false
}

// CACertPathForCluster returns path to the cluster CA certificate for this profile.
//
// It's stored in  <profile-dir>/keys/<proxy>/cas/<cluster>.pem by default.
func (p *ProfileStatus) CACertPathForCluster(cluster string) string {
	// Return an env var override if both valid and present for this identity.
	if path, ok := p.virtualPathFromEnv(VirtualPathCA, VirtualPathCAParams(types.HostCA)); ok {
		return path
	}

	return filepath.Join(keypaths.ProxyKeyDir(p.Dir, p.Name), "cas", cluster+".pem")
}

// KeyPath returns path to the private key for this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>.
func (p *ProfileStatus) KeyPath() string {
	// Return an env var override if both valid and present for this identity.
	if path, ok := p.virtualPathFromEnv(VirtualPathKey, nil); ok {
		return path
	}

	return keypaths.UserKeyPath(p.Dir, p.Name, p.Username)
}

// DatabaseCertPathForCluster returns path to the specified database access
// certificate for this profile, for the specified cluster.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-db/<cluster>/<name>-x509.pem
//
// If the input cluster name is an empty string, the selected cluster in the
// profile will be used.
func (p *ProfileStatus) DatabaseCertPathForCluster(clusterName string, databaseName string) string {
	if clusterName == "" {
		clusterName = p.Cluster
	}

	if path, ok := p.virtualPathFromEnv(VirtualPathDatabase, VirtualPathDatabaseParams(databaseName)); ok {
		return path
	}

	return keypaths.DatabaseCertPath(p.Dir, p.Name, p.Username, clusterName, databaseName)
}

// AppCertPath returns path to the specified app access certificate
// for this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-app/<cluster>/<name>-x509.pem
func (p *ProfileStatus) AppCertPath(name string) string {
	if path, ok := p.virtualPathFromEnv(VirtualPathApp, VirtualPathAppParams(name)); ok {
		return path
	}

	return keypaths.AppCertPath(p.Dir, p.Name, p.Username, p.Cluster, name)
}

// AppLocalCAPath returns the specified app's self-signed localhost CA path for
// this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-app/<cluster>/<name>-localca.pem
func (p *ProfileStatus) AppLocalCAPath(name string) string {
	return keypaths.AppLocalCAPath(p.Dir, p.Name, p.Username, p.Cluster, name)
}

// KubeConfigPath returns path to the specified kubeconfig for this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-kube/<cluster>/<name>-kubeconfig
func (p *ProfileStatus) KubeConfigPath(name string) string {
	if path, ok := p.virtualPathFromEnv(VirtualPathKubernetes, VirtualPathKubernetesParams(name)); ok {
		return path
	}

	return keypaths.KubeConfigPath(p.Dir, p.Name, p.Username, p.Cluster, name)
}

// AppNames returns a list of app names this profile is logged into.
func (p *ProfileStatus) AppNames() (result []string) {
	for _, app := range p.Apps {
		result = append(result, app.Name)
	}
	return result
}

func IsErrorResolvableWithRelogin(err error) bool {
	// Assume that failed handshake is a result of expired credentials.
	return utils.IsHandshakeFailedError(err) || utils.IsCertExpiredError(err) ||
		trace.IsBadParameter(err) || trace.IsTrustError(err)
}

// ProfileOptions contains fields needed to initialize a profile beyond those
// derived directly from a Key.
type ProfileOptions struct {
	ProfileName   string
	ProfileDir    string
	WebProxyAddr  string
	Username      string
	SiteName      string
	KubeProxyAddr string
	IsVirtual     bool
}

// profileFromkey returns a ProfileStatus for the given key and options.
func profileFromKey(key *Key, opts ProfileOptions) (*ProfileStatus, error) {
	sshCert, err := key.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract from the certificate how much longer it will be valid for.
	validUntil := time.Unix(int64(sshCert.ValidBefore), 0)

	// Extract roles from certificate. Note, if the certificate is in old format,
	// this will be empty.
	var roles []string
	rawRoles, ok := sshCert.Extensions[teleport.CertExtensionTeleportRoles]
	if ok {
		roles, err = services.UnmarshalCertRoles(rawRoles)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	sort.Strings(roles)

	// Extract traits from the certificate. Note if the certificate is in the
	// old format, this will be empty.
	var traits wrappers.Traits
	rawTraits, ok := sshCert.Extensions[teleport.CertExtensionTeleportTraits]
	if ok {
		err = wrappers.UnmarshalTraits([]byte(rawTraits), &traits)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	var activeRequests services.RequestIDs
	rawRequests, ok := sshCert.Extensions[teleport.CertExtensionTeleportActiveRequests]
	if ok {
		if err := activeRequests.Unmarshal([]byte(rawRequests)); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	allowedResourcesStr := sshCert.Extensions[teleport.CertExtensionAllowedResources]
	allowedResourceIDs, err := types.ResourceIDsFromString(allowedResourcesStr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract extensions from certificate. This lists the abilities of the
	// certificate (like can the user request a PTY, port forwarding, etc.)
	var extensions []string
	for ext := range sshCert.Extensions {
		if ext == teleport.CertExtensionTeleportRoles ||
			ext == teleport.CertExtensionTeleportTraits ||
			ext == teleport.CertExtensionTeleportRouteToCluster ||
			ext == teleport.CertExtensionTeleportActiveRequests ||
			ext == teleport.CertExtensionAllowedResources {
			continue
		}
		extensions = append(extensions, ext)
	}
	sort.Strings(extensions)

	tlsCert, err := key.TeleportTLSCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsID, err := tlsca.FromSubject(tlsCert.Subject, time.Time{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	appCerts, err := key.AppTLSCertificates()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var apps []tlsca.RouteToApp
	for _, cert := range appCerts {
		tlsID, err := tlsca.FromSubject(cert.Subject, time.Time{})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if tlsID.RouteToApp.PublicAddr != "" {
			apps = append(apps, tlsID.RouteToApp)
		}
	}

	return &ProfileStatus{
		Name: opts.ProfileName,
		Dir:  opts.ProfileDir,
		ProxyURL: url.URL{
			Scheme: "https",
			Host:   opts.WebProxyAddr,
		},
		Username:           opts.Username,
		Logins:             sshCert.ValidPrincipals,
		ValidUntil:         validUntil,
		Extensions:         extensions,
		CriticalOptions:    sshCert.CriticalOptions,
		Roles:              roles,
		Cluster:            opts.SiteName,
		Traits:             traits,
		ActiveRequests:     activeRequests,
		Apps:               apps,
		AWSRolesARNs:       tlsID.AWSRoleARNs,
		IsVirtual:          opts.IsVirtual,
		AllowedResourceIDs: allowedResourceIDs,
	}, nil
}

// ReadProfileFromIdentity creates a "fake" profile from only an identity file,
// allowing the various profile-using subcommands to use identity files as if
// they were profiles. It will set the `username` and `siteName` fields of
// the profileOptions to certificate-provided values if they are unset.
func ReadProfileFromIdentity(key *Key, opts ProfileOptions) (*ProfileStatus, error) {
	// Note: these profile options are largely derived from tsh's makeClient()
	if opts.Username == "" {
		username, err := key.CertUsername()
		if err != nil {
			return nil, trace.Wrap(err)
		}

		opts.Username = username
	}

	if opts.SiteName == "" {
		rootCluster, err := key.RootClusterName()
		if err != nil {
			return nil, trace.Wrap(err)
		}

		opts.SiteName = rootCluster
	}

	opts.IsVirtual = true

	return profileFromKey(key, opts)
}

// ReadProfileStatus reads in the profile as well as the associated certificate
// and returns a *ProfileStatus which can be used to print the status of the
// profile.
func ReadProfileStatus(profileDir string, profileName string) (*ProfileStatus, error) {
	if profileDir == "" {
		return nil, trace.BadParameter("profileDir cannot be empty")
	}

	// Read in the profile for this proxy.
	profile, err := profile.FromDir(profileDir, profileName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Read in the SSH certificate for the user logged into this proxy.
	store, err := NewFSLocalKeyStore(profileDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	idx := KeyIndex{
		ProxyHost:   profile.Name(),
		Username:    profile.Username,
		ClusterName: profile.SiteName,
	}
	key, err := store.GetKey(idx, WithAllCerts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return profileFromKey(key, ProfileOptions{
		ProfileName:   profileName,
		ProfileDir:    profileDir,
		WebProxyAddr:  profile.WebProxyAddr,
		Username:      profile.Username,
		SiteName:      profile.SiteName,
		KubeProxyAddr: profile.KubeProxyAddr,
		IsVirtual:     false,
	})
}

// StatusCurrent returns the active profile status.
func StatusCurrent(profileDir, proxyHost, identityFilePath string) (*ProfileStatus, error) {
	if identityFilePath != "" {
		key, err := KeyFromIdentityFile(identityFilePath)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		profile, err := ReadProfileFromIdentity(key, ProfileOptions{
			ProfileName:  "identity",
			WebProxyAddr: proxyHost,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return profile, nil
	}

	active, _, err := Status(profileDir, proxyHost)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if active == nil {
		return nil, trace.NotFound("not logged in")
	}
	return active, nil
}

// StatusFor returns profile for the specified proxy/user.
func StatusFor(profileDir, proxyHost, username string) (*ProfileStatus, error) {
	active, others, err := Status(profileDir, proxyHost)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, profile := range append(others, active) {
		if profile != nil && profile.Username == username {
			return profile, nil
		}
	}
	return nil, trace.NotFound("no profile for proxy %v and user %v found",
		proxyHost, username)
}

// Status returns the active profile as well as a list of available profiles.
// If no profile is active, Status returns a nil error and nil profile.
func Status(profileDir, proxyHost string) (*ProfileStatus, []*ProfileStatus, error) {
	var err error
	var profileStatus *ProfileStatus
	var others []*ProfileStatus

	// remove ports from proxy host, because profile name is stored
	// by host name
	if proxyHost != "" {
		proxyHost, err = utils.Host(proxyHost)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
	}

	// Construct the full path to the profile requested and make sure it exists.
	profileDir = profile.FullProfilePath(profileDir)
	stat, err := os.Stat(profileDir)
	if err != nil {
		log.Debugf("Failed to stat file: %v.", err)
		if os.IsNotExist(err) {
			return nil, nil, trace.NotFound(err.Error())
		} else if os.IsPermission(err) {
			return nil, nil, trace.AccessDenied(err.Error())
		} else {
			return nil, nil, trace.Wrap(err)
		}
	}
	if !stat.IsDir() {
		return nil, nil, trace.BadParameter("profile path not a directory")
	}

	// use proxyHost as default profile name, or the current profile if
	// no proxyHost was supplied.
	profileName := proxyHost
	if profileName == "" {
		profileName, err = profile.GetCurrentProfileName(profileDir)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, nil, trace.NotFound("not logged in")
			}
			return nil, nil, trace.Wrap(err)
		}
	}

	// Read in the target profile first. If readProfile returns trace.NotFound,
	// that means the profile may have been corrupted (for example keys were
	// deleted but profile exists), treat this as the user not being logged in.
	profileStatus, err = ReadProfileStatus(profileDir, profileName)
	if err != nil {
		log.Debug(err)
		if !trace.IsNotFound(err) {
			return nil, nil, trace.Wrap(err)
		}
		// Make sure the profile is nil, which tsh uses to detect that no
		// active profile exists.
		profileStatus = nil
	}

	// load the rest of the profiles
	profiles, err := profile.ListProfileNames(profileDir)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	for _, name := range profiles {
		if name == profileName {
			// already loaded this one
			continue
		}
		ps, err := ReadProfileStatus(profileDir, name)
		if err != nil {
			log.Debug(err)
			// parts of profile are missing?
			// status skips these files
			if trace.IsNotFound(err) {
				continue
			}
			return nil, nil, trace.Wrap(err)
		}
		others = append(others, ps)
	}

	return profileStatus, others, nil
}

// LoadProfile populates Config with the values stored in the given
// profiles directory. If profileDir is an empty string, the default profile
// directory ~/.tsh is used.
func (c *Config) LoadProfile(profileDir string, proxyName string) error {
	// read the profile:
	cp, err := profile.FromDir(profileDir, ProxyHost(proxyName))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil
		}
		return trace.Wrap(err)
	}

	c.Username = cp.Username
	c.SiteName = cp.SiteName
	c.WebProxyAddr = cp.WebProxyAddr
	c.SSHProxyAddr = cp.SSHProxyAddr
	c.TLSRoutingEnabled = cp.TLSRoutingEnabled
	c.KeysDir = profileDir
	c.AuthConnector = cp.AuthConnector

	c.LocalForwardPorts, err = ParsePortForwardSpec(cp.ForwardedPorts)
	if err != nil {
		log.Warnf("Unable to parse port forwarding in user profile: %v.", err)
	}

	c.DynamicForwardedPorts, err = ParseDynamicPortForwardSpec(cp.DynamicForwardedPorts)
	if err != nil {
		log.Warnf("Unable to parse dynamic port forwarding in user profile: %v.", err)
	}

	return nil
}

// SaveProfile updates the given profiles directory with the current configuration
// If profileDir is an empty string, the default ~/.tsh is used
func (c *Config) SaveProfile(dir string, makeCurrent bool) error {
	if c.WebProxyAddr == "" {
		return nil
	}

	dir = profile.FullProfilePath(dir)

	var cp profile.Profile
	cp.Username = c.Username
	cp.WebProxyAddr = c.WebProxyAddr
	cp.SSHProxyAddr = c.SSHProxyAddr
	cp.ForwardedPorts = c.LocalForwardPorts.String()
	cp.SiteName = c.SiteName
	cp.TLSRoutingEnabled = c.TLSRoutingEnabled
	cp.AuthConnector = c.AuthConnector

	if err := cp.SaveToDir(dir, makeCurrent); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// ParsedProxyHost holds the hostname and Web & SSH proxy addresses
// parsed out of a WebProxyAddress string.
type ParsedProxyHost struct {
	Host string

	// UsingDefaultWebProxyPort means that the port in WebProxyAddr was
	// supplied by ParseProxyHost function rather than ProxyHost string
	// itself.
	UsingDefaultWebProxyPort bool
	WebProxyAddr             string
	SSHProxyAddr             string
}

// ParseProxyHost parses a ProxyHost string of the format <hostname>:<proxy_web_port>,<proxy_ssh_port>
// and returns the parsed components.
//
// There are several "default" ports that the Web Proxy service may use, and if the port is not
// specified in the supplied proxyHost string
//
// If a definitive answer is not possible (e.g.  no proxy port is specified in
// the supplied string), ParseProxyHost() will supply default versions and flag
// that a default value is being used in the returned `ParsedProxyHost`
func ParseProxyHost(proxyHost string) (*ParsedProxyHost, error) {
	host, port, err := net.SplitHostPort(proxyHost)
	if err != nil {
		host = proxyHost
		port = ""
	}

	// set the default values of the port strings. One, both, or neither may
	// be overridden by the port string parsing below.
	usingDefaultWebProxyPort := true
	webPort := strconv.Itoa(defaults.HTTPListenPort)
	sshPort := strconv.Itoa(defaults.SSHProxyListenPort)

	// Split the port string out into at most two parts, the proxy port and
	// ssh port. Any more that 2 parts will be considered an error.
	parts := strings.Split(port, ",")

	switch {
	// Default ports for both the SSH and Web proxy.
	case len(parts) == 0:
		break

	// User defined HTTP proxy port, default SSH proxy port.
	case len(parts) == 1:
		if text := strings.TrimSpace(parts[0]); len(text) > 0 {
			webPort = text
			usingDefaultWebProxyPort = false
		}

	// User defined HTTP and SSH proxy ports.
	case len(parts) == 2:
		if text := strings.TrimSpace(parts[0]); len(text) > 0 {
			webPort = text
			usingDefaultWebProxyPort = false
		}
		if text := strings.TrimSpace(parts[1]); len(text) > 0 {
			sshPort = text
		}

	default:
		return nil, trace.BadParameter("unable to parse port: %v", port)
	}

	result := &ParsedProxyHost{
		Host:                     host,
		UsingDefaultWebProxyPort: usingDefaultWebProxyPort,
		WebProxyAddr:             net.JoinHostPort(host, webPort),
		SSHProxyAddr:             net.JoinHostPort(host, sshPort),
	}
	return result, nil
}

// ParseProxyHost parses the proxyHost string and updates the config.
//
// Format of proxyHost string:
//
//	proxy_web_addr:<proxy_web_port>,<proxy_ssh_port>
func (c *Config) ParseProxyHost(proxyHost string) error {
	parsedAddrs, err := ParseProxyHost(proxyHost)
	if err != nil {
		return trace.Wrap(err)
	}
	c.WebProxyAddr = parsedAddrs.WebProxyAddr
	c.SSHProxyAddr = parsedAddrs.SSHProxyAddr
	return nil
}

// WebProxyHostPort returns the host and port of the web proxy.
func (c *Config) WebProxyHostPort() (string, int) {
	if c.WebProxyAddr != "" {
		addr, err := utils.ParseAddr(c.WebProxyAddr)
		if err == nil {
			return addr.Host(), addr.Port(defaults.HTTPListenPort)
		}
	}
	return "unknown", defaults.HTTPListenPort
}

// WebProxyHost returns the web proxy host without the port number.
func (c *Config) WebProxyHost() string {
	host, _ := c.WebProxyHostPort()
	return host
}

// WebProxyPort returns the port of the web proxy.
func (c *Config) WebProxyPort() int {
	_, port := c.WebProxyHostPort()
	return port
}

// SSHProxyHostPort returns the host and port of the SSH proxy.
func (c *Config) SSHProxyHostPort() (string, int) {
	if c.SSHProxyAddr != "" {
		addr, err := utils.ParseAddr(c.SSHProxyAddr)
		if err == nil {
			return addr.Host(), addr.Port(defaults.SSHProxyListenPort)
		}
	}

	webProxyHost, _ := c.WebProxyHostPort()
	return webProxyHost, defaults.SSHProxyListenPort
}

// GetKubeTLSServerName returns k8s server name used in KUBECONFIG to leverage TLS Routing.
func GetKubeTLSServerName(k8host string) string {
	isIPFormat := net.ParseIP(k8host) != nil

	if k8host == "" || isIPFormat {
		// If proxy is configured without public_addr set the ServerName to the 'kube.teleport.cluster.local' value.
		// The k8s server name needs to be a valid hostname but when public_addr is missing from proxy settings
		// the web_listen_addr is used thus webHost will contain local proxy IP address like: 0.0.0.0 or 127.0.0.1
		// TODO(smallinsky) UPGRADE IN 10.0. Switch to KubeTeleportProxyALPNPrefix instead.
		return addSubdomainPrefix(constants.APIDomain, constants.KubeSNIPrefix)
	}
	// TODO(smallinsky) UPGRADE IN 10.0. Switch to KubeTeleportProxyALPNPrefix instead.
	return addSubdomainPrefix(k8host, constants.KubeSNIPrefix)
}

func addSubdomainPrefix(domain, prefix string) string {
	return fmt.Sprintf("%s%s", prefix, domain)
}

// ProxyHost returns the hostname of the proxy server (without any port numbers)
func ProxyHost(proxyHost string) string {
	host, _, err := net.SplitHostPort(proxyHost)
	if err != nil {
		return proxyHost
	}
	return host
}

// ProxySpecified returns true if proxy has been specified.
func (c *Config) ProxySpecified() bool {
	return c.WebProxyAddr != ""
}

// DefaultResourceFilter returns the default list resource request.
func (c *Config) DefaultResourceFilter() *proto.ListResourcesRequest {
	return &proto.ListResourcesRequest{
		Namespace:           c.Namespace,
		Labels:              c.Labels,
		SearchKeywords:      c.SearchKeywords,
		PredicateExpression: c.PredicateExpression,
	}
}

// TeleportClient is a wrapper around SSH client with teleport specific
// workflow built in.
// TeleportClient is NOT safe for concurrent use.
type TeleportClient struct {
	Config
	localAgent *LocalKeyAgent

	// OnShellCreated gets called when the shell is created. It's
	// safe to keep it nil.
	OnShellCreated ShellCreatedCallback

	// eventsCh is a channel used to inform clients about events have that
	// occurred during the session.
	eventsCh chan events.EventFields

	// Note: there's no mutex guarding this or localAgent, making
	// TeleportClient NOT safe for concurrent use.
	lastPing *webclient.PingResponse
}

// ShellCreatedCallback can be supplied for every teleport client. It will
// be called right after the remote shell is created, but the session
// hasn't begun yet.
//
// It allows clients to cancel SSH action
type ShellCreatedCallback func(s *tracessh.Session, c *tracessh.Client, terminal io.ReadWriteCloser) (exit bool, err error)

// NewClient creates a TeleportClient object and fully configures it
func NewClient(c *Config) (tc *TeleportClient, err error) {
	if len(c.JumpHosts) > 1 {
		return nil, trace.BadParameter("only one jump host is supported, got %v", len(c.JumpHosts))
	}
	// validate configuration
	if c.Username == "" {
		c.Username, err = Username()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		log.Infof("No teleport login given. defaulting to %s", c.Username)
	}
	if c.WebProxyAddr == "" {
		return nil, trace.BadParameter("No proxy address specified, missed --proxy flag?")
	}
	if c.HostLogin == "" {
		c.HostLogin, err = Username()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		log.Infof("no host login given. defaulting to %s", c.HostLogin)
	}
	if c.KeyTTL == 0 {
		c.KeyTTL = apidefaults.CertDuration
	}
	c.Namespace = types.ProcessNamespace(c.Namespace)

	tc = &TeleportClient{
		Config: *c,
	}

	if tc.Stdout == nil {
		tc.Stdout = os.Stdout
	}
	if tc.Stderr == nil {
		tc.Stderr = os.Stderr
	}
	if tc.Stdin == nil {
		tc.Stdin = os.Stdin
	}

	// Create a buffered channel to hold events that occurred during this session.
	// This channel must be buffered because the SSH connection directly feeds
	// into it. Delays in pulling messages off the global SSH request channel
	// could lead to the connection hanging.
	tc.eventsCh = make(chan events.EventFields, 1024)

	localAgentCfg := LocalAgentConfig{
		Agent:      c.Agent,
		ProxyHost:  tc.WebProxyHost(),
		Username:   c.Username,
		KeysOption: c.AddKeysToAgent,
		Insecure:   c.InsecureSkipVerify,
		SiteName:   tc.SiteName,
	}

	// sometimes we need to use external auth without using local auth
	// methods, e.g. in automation daemons.
	if c.SkipLocalAuth {
		if len(c.AuthMethods) == 0 {
			return nil, trace.BadParameter("SkipLocalAuth is true but no AuthMethods provided")
		}
		localAgentCfg.Keystore = noLocalKeyStore{}
		if c.PreloadKey != nil {
			localAgentCfg.Keystore, err = NewMemLocalKeyStore(c.KeysDir)
			if err != nil {
				return nil, trace.Wrap(err)
			}
		}
	} else if c.AddKeysToAgent == AddKeysToAgentOnly {
		localAgentCfg.Keystore, err = NewMemLocalKeyStore(c.KeysDir)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		localAgentCfg.Keystore, err = NewFSLocalKeyStore(c.KeysDir)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// initialize the local agent (auth agent which uses local SSH keys signed by the CA):
	tc.localAgent, err = NewLocalAgent(localAgentCfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if tc.HostKeyCallback == nil {
		tc.HostKeyCallback = tc.localAgent.CheckHostSignature
	}

	if c.PreloadKey != nil {
		// Extract the username from the key - it's needed for GetKey()
		// to function properly.
		tc.localAgent.username, err = c.PreloadKey.CertUsername()
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// Add the key to the agent and keystore.
		if err := tc.AddKey(c.PreloadKey); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return tc, nil
}

// LoadKeyForCluster fetches a cluster-specific SSH key and loads it into the
// SSH agent.
func (tc *TeleportClient) LoadKeyForCluster(clusterName string) error {
	if tc.localAgent == nil {
		return trace.BadParameter("TeleportClient.LoadKeyForCluster called on a client without localAgent")
	}
	if err := tc.localAgent.LoadKeyForCluster(clusterName); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// LocalAgent is a getter function for the client's local agent
func (tc *TeleportClient) LocalAgent() *LocalKeyAgent {
	return tc.localAgent
}

// RootClusterName returns root cluster name.
func (tc *TeleportClient) RootClusterName(ctx context.Context) (string, error) {
	key, err := tc.LocalAgent().GetCoreKey()
	if err != nil {
		return "", trace.Wrap(err)
	}
	name, err := key.RootClusterName()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return name, nil
}

// getTargetNodes returns a list of node addresses this SSH command needs to
// operate on.
func (tc *TeleportClient) getTargetNodes(ctx context.Context, proxy *ProxyClient) ([]string, error) {
	// use the target node that was explicitly provided if valid
	if len(tc.Labels) == 0 {
		// detect the common error when users use host:port address format
		_, port, err := net.SplitHostPort(tc.Host)
		// client has used host:port notation
		if err == nil {
			return nil, trace.BadParameter("please use ssh subcommand with '--port=%v' flag instead of semicolon", port)
		}

		addr := net.JoinHostPort(tc.Host, strconv.Itoa(tc.HostPort))
		return []string{addr}, nil
	}

	// find the nodes matching the labels that were provided
	nodes, err := proxy.FindNodesByFilters(ctx, *tc.DefaultResourceFilter())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	retval := make([]string, 0, len(nodes))
	for i := 0; i < len(nodes); i++ {
		// always dial nodes by UUID
		retval = append(retval, fmt.Sprintf("%s:0", nodes[i].GetName()))
	}

	return retval, nil
}

// watchCloser is a wrapper around a services.Watcher
// which holds a closer that must be called after the watcher
// is closed.
type watchCloser struct {
	types.Watcher
	io.Closer
}

func (w watchCloser) Close() error {
	return trace.NewAggregate(w.Watcher.Close(), w.Closer.Close())
}

func (tc *TeleportClient) startPortForwarding(ctx context.Context, nodeClient *NodeClient) error {
	for _, fp := range tc.Config.LocalForwardPorts {
		addr := net.JoinHostPort(fp.SrcIP, strconv.Itoa(fp.SrcPort))
		socket, err := net.Listen("tcp", addr)
		if err != nil {
			return trace.Errorf("Failed to bind to %v: %v.", addr, err)
		}
		go nodeClient.listenAndForward(ctx, socket, addr, net.JoinHostPort(fp.DestHost, strconv.Itoa(fp.DestPort)))
	}
	for _, fp := range tc.Config.DynamicForwardedPorts {
		addr := net.JoinHostPort(fp.SrcIP, strconv.Itoa(fp.SrcPort))
		socket, err := net.Listen("tcp", addr)
		if err != nil {
			return trace.Errorf("Failed to bind to %v: %v.", addr, err)
		}
		go nodeClient.dynamicListenAndForward(ctx, socket, addr)
	}
	return nil
}

// PlayFile plays the recorded session from a tar file
func PlayFile(ctx context.Context, tarFile io.Reader, sid string) error {
	var sessionEvents []events.EventFields
	var stream []byte
	protoReader := events.NewProtoReader(tarFile)
	playbackDir, err := os.MkdirTemp("", "playback")
	if err != nil {
		return trace.Wrap(err)
	}
	defer os.RemoveAll(playbackDir)
	w, err := events.WriteForSSHPlayback(ctx, session.ID(sid), protoReader, playbackDir)
	if err != nil {
		return trace.Wrap(err)
	}
	sessionEvents, err = w.SessionEvents()
	if err != nil {
		return trace.Wrap(err)
	}
	stream, err = w.SessionChunks()
	if err != nil {
		return trace.Wrap(err)
	}

	return playSession(sessionEvents, stream)
}

func (tc *TeleportClient) uploadConfig(ctx context.Context, tpl scp.Config, port int, args []string) (config *scpConfig, err error) {
	// args are guaranteed to have len(args) > 1
	filesToUpload := args[:len(args)-1]
	// copy everything except the last arg (the destination)
	destPath := args[len(args)-1]

	// If more than a single file were provided, scp must be in directory mode
	// and the target on the remote host needs to be a directory.
	var directoryMode bool
	if len(filesToUpload) > 1 {
		directoryMode = true
	}

	dest, addr, err := getSCPDestination(destPath, port)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tpl.RemoteLocation = dest.Path
	tpl.Flags.Target = filesToUpload
	tpl.Flags.DirectoryMode = directoryMode

	cmd, err := scp.CreateUploadCommand(tpl)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &scpConfig{
		cmd:       cmd,
		addr:      addr,
		hostLogin: dest.Login,
	}, nil
}

func (tc *TeleportClient) downloadConfig(ctx context.Context, tpl scp.Config, port int, args []string) (config *scpConfig, err error) {
	// args are guaranteed to have len(args) > 1
	src, addr, err := getSCPDestination(args[0], port)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tpl.RemoteLocation = src.Path
	tpl.Flags.Target = args[1:]

	cmd, err := scp.CreateDownloadCommand(tpl)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &scpConfig{
		cmd:       cmd,
		addr:      addr,
		hostLogin: src.Login,
	}, nil
}

type scpConfig struct {
	cmd       scp.Command
	addr      string
	hostLogin string
}

func getSCPDestination(target string, port int) (dest *scp.Destination, addr string, err error) {
	dest, err = scp.ParseSCPDestination(target)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	addr = net.JoinHostPort(dest.Host.Host(), strconv.Itoa(port))
	return dest, addr, nil
}

func isRemoteDest(name string) bool {
	return strings.ContainsRune(name, ':')
}

// runCommand executes a given bash command on an established NodeClient.
func (tc *TeleportClient) runCommand(ctx context.Context, nodeClient *NodeClient, command []string) error {
	nodeSession, err := newSession(ctx, nodeClient, nil, tc.Config.Env, tc.Stdin, tc.Stdout, tc.Stderr, tc.EnableEscapeSequences)
	if err != nil {
		return trace.Wrap(err)
	}
	defer nodeSession.Close()
	if err := nodeSession.runCommand(ctx, types.SessionPeerMode, command, tc.OnShellCreated, tc.Config.Interactive); err != nil {
		originErr := trace.Unwrap(err)
		exitErr, ok := originErr.(*ssh.ExitError)
		if ok {
			tc.ExitStatus = exitErr.ExitStatus()
		} else {
			// if an error occurs, but no exit status is passed back, GoSSH returns
			// a generic error like this. in this case the error message is printed
			// to stderr by the remote process so we have to quietly return 1:
			if strings.Contains(originErr.Error(), "exited without exit status") {
				tc.ExitStatus = 1
			}
		}

		return trace.Wrap(err)
	}

	return nil
}

// runShell starts an interactive SSH session/shell.
// sessionID : when empty, creates a new shell. otherwise it tries to join the existing session.
func (tc *TeleportClient) runShell(ctx context.Context, nodeClient *NodeClient, mode types.SessionParticipantMode, sessToJoin types.SessionTracker, beforeStart func(io.Writer)) error {
	env := make(map[string]string)
	env[teleport.EnvSSHJoinMode] = string(mode)
	env[teleport.EnvSSHSessionReason] = tc.Config.Reason
	env[teleport.EnvSSHSessionDisplayParticipantRequirements] = strconv.FormatBool(tc.Config.DisplayParticipantRequirements)
	encoded, err := json.Marshal(&tc.Config.Invited)
	if err != nil {
		return trace.Wrap(err)
	}

	env[teleport.EnvSSHSessionInvited] = string(encoded)
	for key, value := range tc.Env {
		env[key] = value
	}

	nodeSession, err := newSession(ctx, nodeClient, sessToJoin, env, tc.Stdin, tc.Stdout, tc.Stderr, tc.EnableEscapeSequences)
	if err != nil {
		return trace.Wrap(err)
	}
	if err = nodeSession.runShell(ctx, mode, beforeStart, tc.OnShellCreated); err != nil {
		switch e := trace.Unwrap(err).(type) {
		case *ssh.ExitError:
			tc.ExitStatus = e.ExitStatus()
		case *ssh.ExitMissingError:
			tc.ExitStatus = 1
		}

		return trace.Wrap(err)
	}
	if nodeSession.ExitMsg == "" {
		fmt.Fprintln(tc.Stderr, "the connection was closed on the remote side on ", time.Now().Format(time.RFC822))
	} else {
		fmt.Fprintln(tc.Stderr, nodeSession.ExitMsg)
	}
	return nil
}

// getProxyLogin determines which SSH principal to use when connecting to proxy.
func (tc *TeleportClient) getProxySSHPrincipal() string {
	proxyPrincipal := tc.Config.HostLogin
	if tc.DefaultPrincipal != "" {
		proxyPrincipal = tc.DefaultPrincipal
	}
	if len(tc.JumpHosts) > 1 && tc.JumpHosts[0].Username != "" {
		log.Debugf("Setting proxy login to jump host's parameter user %q", tc.JumpHosts[0].Username)
		proxyPrincipal = tc.JumpHosts[0].Username
	}
	// see if we already have a signed key in the cache, we'll use that instead
	if (!tc.Config.SkipLocalAuth || tc.UseKeyPrincipals) && tc.localAgent != nil {
		signers, err := tc.localAgent.Signers()
		if err != nil || len(signers) == 0 {
			return proxyPrincipal
		}
		cert, ok := signers[0].PublicKey().(*ssh.Certificate)
		if ok && len(cert.ValidPrincipals) > 0 {
			return cert.ValidPrincipals[0]
		}
	}
	return proxyPrincipal
}

const unconfiguredPublicAddrMsg = `WARNING:

The following error has occurred as Teleport does not recognise the address
that is being used to connect to it. This usually indicates that the
'public_addr' configuration option of the 'proxy_service' has not been
set to match the address you are hosting the proxy on.

If 'public_addr' is configured correctly, this could be an indicator of an
attempted man-in-the-middle attack.
`

// formatConnectToProxyErr adds additional user actionable advice to errors
// that are raised during ConnectToProxy.
func formatConnectToProxyErr(err error) error {
	if err == nil {
		return nil
	}

	// Handles the error that occurs when you connect to the Proxy SSH service
	// and the Proxy does not have a correct `public_addr` configured, and the
	// system is configured with non-multiplexed ports.
	if utils.IsHandshakeFailedError(err) {
		const principalStr = "not in the set of valid principals for given certificate"
		if strings.Contains(err.Error(), principalStr) {
			return trace.Wrap(err, unconfiguredPublicAddrMsg)
		}
	}

	return err
}

// makeProxySSHClient creates an SSH client by following steps:
//  1. If the current proxy supports TLS Routing and JumpHost address was not provided use TLSWrapper.
//  2. Check JumpHost raw SSH port or Teleport proxy address.
//     In case of proxy web address check if the proxy supports TLS Routing and connect to the proxy with TLSWrapper
//  3. Dial sshProxyAddr with raw SSH Dialer where sshProxyAddress is proxy ssh address or JumpHost address if
//     JumpHost address was provided.
func makeProxySSHClient(ctx context.Context, tc *TeleportClient, sshConfig *ssh.ClientConfig) (*tracessh.Client, error) {
	// Use TLS Routing dialer only if proxy support TLS Routing and JumpHost was not set.
	if tc.Config.TLSRoutingEnabled && len(tc.JumpHosts) == 0 {
		log.Infof("Connecting to proxy=%v login=%q using TLS Routing", tc.Config.WebProxyAddr, sshConfig.User)
		c, err := makeProxySSHClientWithTLSWrapper(ctx, tc, sshConfig, tc.Config.WebProxyAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		log.Infof("Successful auth with proxy %v.", tc.Config.WebProxyAddr)
		return c, nil
	}

	sshProxyAddr := tc.Config.SSHProxyAddr

	// Handle situation where a Jump Host was set to proxy web address and Teleport supports TLS Routing.
	if len(tc.JumpHosts) > 0 {
		sshProxyAddr = tc.JumpHosts[0].Addr.Addr
		// Check if JumpHost address is a proxy web address.
		resp, err := webclient.Find(&webclient.Config{Context: ctx, ProxyAddr: sshProxyAddr, Insecure: tc.InsecureSkipVerify})
		// If JumpHost address is a proxy web port and proxy supports TLSRouting dial proxy with TLSWrapper.
		if err == nil && resp.Proxy.TLSRoutingEnabled {
			log.Infof("Connecting to proxy=%v login=%q using TLS Routing JumpHost", sshProxyAddr, sshConfig.User)
			c, err := makeProxySSHClientWithTLSWrapper(ctx, tc, sshConfig, sshProxyAddr)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			log.Infof("Successful auth with proxy %v.", sshProxyAddr)
			return c, nil
		}
	}

	log.Infof("Connecting to proxy=%v login=%q", sshProxyAddr, sshConfig.User)
	client, err := makeProxySSHClientDirect(ctx, tc, sshConfig, sshProxyAddr)
	if err != nil {
		if utils.IsHandshakeFailedError(err) {
			return nil, trace.AccessDenied("failed to authenticate with proxy %v: %v", sshProxyAddr, err)
		}

		return nil, trace.Wrap(err, "failed to authenticate with proxy %v", sshProxyAddr)
	}
	log.Infof("Successful auth with proxy %v.", sshProxyAddr)
	return client, nil
}

func makeProxySSHClientDirect(ctx context.Context, tc *TeleportClient, sshConfig *ssh.ClientConfig, proxyAddr string) (*tracessh.Client, error) {
	dialer := proxy.DialerFromEnvironment(tc.Config.SSHProxyAddr)
	return dialer.Dial(ctx, "tcp", proxyAddr, sshConfig)
}

func makeProxySSHClientWithTLSWrapper(ctx context.Context, tc *TeleportClient, sshConfig *ssh.ClientConfig, proxyAddr string) (*tracessh.Client, error) {
	tlsConfig, err := tc.loadTLSConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsConfig.NextProtos = []string{string(alpncommon.ProtocolProxySSH)}
	dialer := proxy.DialerFromEnvironment(tc.Config.WebProxyAddr, proxy.WithALPNDialer(tlsConfig))
	return dialer.Dial(ctx, "tcp", proxyAddr, sshConfig)
}

func (tc *TeleportClient) rootClusterName() (string, error) {
	if tc.localAgent == nil {
		return "", trace.NotFound("cannot load root cluster name without local agent")
	}
	tlsKey, err := tc.localAgent.GetCoreKey()
	if err != nil {
		return "", trace.Wrap(err)
	}
	rootClusterName, err := tlsKey.RootClusterName()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return rootClusterName, nil
}

// proxyClusterGuesser matches client SSH certificates to the target cluster of
// an SSH proxy. It uses an ssh.HostKeyCallback to infer the cluster name from
// the proxy host certificate. It then passes that name to signersForCluster to
// get the SSH certificates for that cluster.
type proxyClusterGuesser struct {
	clusterName string

	nextHostKeyCallback ssh.HostKeyCallback
	signersForCluster   func(context.Context, string) ([]ssh.Signer, error)
}

func newProxyClusterGuesser(nextHostKeyCallback ssh.HostKeyCallback, signersForCluster func(context.Context, string) ([]ssh.Signer, error)) *proxyClusterGuesser {
	return &proxyClusterGuesser{
		nextHostKeyCallback: nextHostKeyCallback,
		signersForCluster:   signersForCluster,
	}
}

func (g *proxyClusterGuesser) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return trace.BadParameter("remote proxy did not present a host certificate")
	}
	g.clusterName = cert.Permissions.Extensions[utils.CertExtensionAuthority]
	if g.clusterName == "" {
		log.Debugf("Target SSH server %q does not have a cluster name embedded in their certificate; will use all available client certificates to authenticate", hostname)
	}
	if g.nextHostKeyCallback != nil {
		return g.nextHostKeyCallback(hostname, remote, key)
	}
	return nil
}

func (g *proxyClusterGuesser) authMethod(ctx context.Context) ssh.AuthMethod {
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return g.signersForCluster(ctx, g.clusterName)
	})
}

// WithoutJumpHosts executes the given function with a Teleport client that has
// no JumpHosts set, i.e. presumably falling back to the proxy specified in the
// profile.
func (tc *TeleportClient) WithoutJumpHosts(fn func(tcNoJump *TeleportClient) error) error {
	storedJumpHosts := tc.JumpHosts
	tc.JumpHosts = nil
	err := fn(tc)
	tc.JumpHosts = storedJumpHosts
	return trace.Wrap(err)
}

// Logout removes certificate and key for the currently logged in user from
// the filesystem and agent.
func (tc *TeleportClient) Logout() error {
	if tc.localAgent == nil {
		return nil
	}
	return tc.localAgent.DeleteKey()
}

// LogoutAll removes all certificates for all users from the filesystem
// and agent.
func (tc *TeleportClient) LogoutAll() error {
	if tc.localAgent == nil {
		return nil
	}
	if err := tc.localAgent.DeleteKeys(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// PingAndShowMOTD pings the Teleport Proxy and displays the Message Of The Day if it's available.
func (tc *TeleportClient) PingAndShowMOTD(ctx context.Context) (*webclient.PingResponse, error) {
	pr, err := tc.Ping(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if pr.Auth.HasMessageOfTheDay {
		err = tc.ShowMOTD(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return pr, nil
}

// GetWebConfig retrieves Teleport proxy web config
func (tc *TeleportClient) GetWebConfig(ctx context.Context) (*webclient.WebConfig, error) {
	cfg, err := GetWebConfig(ctx, tc.WebProxyAddr, tc.InsecureSkipVerify)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return cfg, nil
}

// Login logs the user into a Teleport cluster by talking to a Teleport proxy.
//
// The returned Key should typically be passed to ActivateKey in order to
// update local agent state.
func (tc *TeleportClient) Login(ctx context.Context) (*Key, error) {
	// Ping the endpoint to see if it's up and find the type of authentication
	// supported, also show the message of the day if available.
	pr, err := tc.PingAndShowMOTD(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// generate a new keypair. the public key will be signed via proxy if client's
	// password+OTP are valid
	key, err := GenerateRSAKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var response *auth.SSHLoginResponse
	var username string
	switch authType := pr.Auth.Type; {
	case authType == constants.Local && pr.Auth.Local != nil && pr.Auth.Local.Name == constants.PasswordlessConnector:
		// Sanity check settings.
		if !pr.Auth.AllowPasswordless {
			return nil, trace.BadParameter("passwordless disallowed by cluster settings")
		}
		response, err = tc.pwdlessLogin(ctx, key.MarshalSSHPublicKey())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		username = response.Username
	case authType == constants.Local:
		response, err = tc.localLogin(ctx, pr.Auth.SecondFactor, key.MarshalSSHPublicKey())
		if err != nil {
			return nil, trace.Wrap(err)
		}
	case authType == constants.OIDC:
		response, err = tc.ssoLogin(ctx, pr.Auth.OIDC.Name, key.MarshalSSHPublicKey(), constants.OIDC)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		username = response.Username
	case authType == constants.SAML:
		response, err = tc.ssoLogin(ctx, pr.Auth.SAML.Name, key.MarshalSSHPublicKey(), constants.SAML)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		username = response.Username
	case authType == constants.Github:
		response, err = tc.ssoLogin(ctx, pr.Auth.Github.Name, key.MarshalSSHPublicKey(), constants.Github)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		username = response.Username
	default:
		return nil, trace.BadParameter("unsupported authentication type: %q", pr.Auth.Type)
	}
	// Use proxy identity?
	if username != "" {
		tc.Username = username
		if tc.localAgent != nil {
			tc.localAgent.username = username
		}
	}

	// Check that a host certificate for at least one cluster was returned.
	if len(response.HostSigners) == 0 {
		return nil, trace.BadParameter("bad response from the server: expected at least one certificate, got 0")
	}

	// extract the new certificate out of the response
	key.Cert = response.Cert
	key.TLSCert = response.TLSCert
	key.TrustedCA = response.HostSigners

	// Store the requested cluster name in the key.
	key.ClusterName = tc.SiteName
	if key.ClusterName == "" {
		rootClusterName := key.TrustedCA[0].ClusterName
		key.ClusterName = rootClusterName
		tc.SiteName = rootClusterName
	}

	return key, nil
}

func (tc *TeleportClient) pwdlessLogin(ctx context.Context, pubKey []byte) (*auth.SSHLoginResponse, error) {
	// Only pass on the user if explicitly set, otherwise let the credential
	// picker kick in.
	user := ""
	if tc.ExplicitUsername {
		user = tc.Username
	}

	response, err := SSHAgentPasswordlessLogin(ctx, SSHLoginPasswordless{
		SSHLogin: SSHLogin{
			ProxyAddr:      tc.WebProxyAddr,
			PubKey:         pubKey,
			TTL:            tc.KeyTTL,
			Insecure:       tc.InsecureSkipVerify,
			Pool:           loopbackPool(tc.WebProxyAddr),
			Compatibility:  tc.CertificateFormat,
			RouteToCluster: tc.SiteName,
		},
		User:                    user,
		AuthenticatorAttachment: tc.AuthenticatorAttachment,
		StderrOverride:          tc.Stderr,
	})

	return response, trace.Wrap(err)
}

func (tc *TeleportClient) localLogin(ctx context.Context, secondFactor constants.SecondFactorType, pub []byte) (*auth.SSHLoginResponse, error) {
	var err error
	var response *auth.SSHLoginResponse

	// TODO(awly): mfa: ideally, clients should always go through mfaLocalLogin
	// (with a nop MFA challenge if no 2nd factor is required). That way we can
	// deprecate the direct login endpoint.
	switch secondFactor {
	case constants.SecondFactorOff, constants.SecondFactorOTP:
		response, err = tc.directLogin(ctx, secondFactor, pub)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	case constants.SecondFactorU2F, constants.SecondFactorWebauthn, constants.SecondFactorOn, constants.SecondFactorOptional:
		response, err = tc.mfaLocalLogin(ctx, pub)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	default:
		return nil, trace.BadParameter("unsupported second factor type: %q", secondFactor)
	}

	return response, nil
}

// directLogin asks for a password + HOTP token, makes a request to CA via proxy
func (tc *TeleportClient) directLogin(ctx context.Context, secondFactorType constants.SecondFactorType, pub []byte) (*auth.SSHLoginResponse, error) {
	password, err := tc.AskPassword(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Only ask for a second factor if it's enabled.
	var otpToken string
	if secondFactorType == constants.SecondFactorOTP {
		otpToken, err = tc.AskOTP(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// Ask the CA (via proxy) to sign our public key:
	response, err := SSHAgentLogin(ctx, SSHLoginDirect{
		SSHLogin: SSHLogin{
			ProxyAddr:      tc.WebProxyAddr,
			PubKey:         pub,
			TTL:            tc.KeyTTL,
			Insecure:       tc.InsecureSkipVerify,
			Pool:           loopbackPool(tc.WebProxyAddr),
			Compatibility:  tc.CertificateFormat,
			RouteToCluster: tc.SiteName,
		},
		User:     tc.Username,
		Password: password,
		OTPToken: otpToken,
	})

	return response, trace.Wrap(err)
}

// mfaLocalLogin asks for a password and performs the challenge-response authentication
func (tc *TeleportClient) mfaLocalLogin(ctx context.Context, pub []byte) (*auth.SSHLoginResponse, error) {
	password, err := tc.AskPassword(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	response, err := SSHAgentMFALogin(ctx, SSHLoginMFA{
		SSHLogin: SSHLogin{
			ProxyAddr:      tc.WebProxyAddr,
			PubKey:         pub,
			TTL:            tc.KeyTTL,
			Insecure:       tc.InsecureSkipVerify,
			Pool:           loopbackPool(tc.WebProxyAddr),
			Compatibility:  tc.CertificateFormat,
			RouteToCluster: tc.SiteName,
		},
		User:                    tc.Username,
		Password:                password,
		AuthenticatorAttachment: tc.AuthenticatorAttachment,
		PreferOTP:               tc.PreferOTP,
		AllowStdinHijack:        tc.AllowStdinHijack,
	})

	return response, trace.Wrap(err)
}

// SSOLoginFunc is a function used in tests to mock SSO logins.
type SSOLoginFunc func(ctx context.Context, connectorID string, pub []byte, protocol string) (*auth.SSHLoginResponse, error)

// samlLogin opens browser window and uses OIDC or SAML redirect cycle with browser
func (tc *TeleportClient) ssoLogin(ctx context.Context, connectorID string, pub []byte, protocol string) (*auth.SSHLoginResponse, error) {
	if tc.MockSSOLogin != nil {
		// sso login response is being mocked for testing purposes
		return tc.MockSSOLogin(ctx, connectorID, pub, protocol)
	}
	// ask the CA (via proxy) to sign our public key:
	response, err := SSHAgentSSOLogin(ctx, SSHLoginSSO{
		SSHLogin: SSHLogin{
			ProxyAddr:      tc.WebProxyAddr,
			PubKey:         pub,
			TTL:            tc.KeyTTL,
			Insecure:       tc.InsecureSkipVerify,
			Pool:           loopbackPool(tc.WebProxyAddr),
			Compatibility:  tc.CertificateFormat,
			RouteToCluster: tc.SiteName,
		},
		ConnectorID: connectorID,
		Protocol:    protocol,
		BindAddr:    tc.BindAddr,
		Browser:     tc.Browser,
	}, nil)
	return response, trace.Wrap(err)
}

// Ping makes a ping request to the proxy, and updates tc based on the
// response. The successful ping response is cached, multiple calls to Ping
// will return the original response and skip the round-trip.
//
// Ping can be called for its side-effect of applying the proxy-provided
// settings (such as various listening addresses).
func (tc *TeleportClient) Ping(ctx context.Context) (*webclient.PingResponse, error) {
	// If, at some point, there's a need to bypass this caching, consider
	// adding a bool argument. At the time of writing this we always want to
	// cache.
	if tc.lastPing != nil {
		return tc.lastPing, nil
	}
	pr, err := webclient.Ping(&webclient.Config{
		Context:       ctx,
		ProxyAddr:     tc.WebProxyAddr,
		Insecure:      tc.InsecureSkipVerify,
		Pool:          loopbackPool(tc.WebProxyAddr),
		ConnectorName: tc.AuthConnector,
		ExtraHeaders:  tc.ExtraProxyHeaders,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// If version checking was requested and the server advertises a minimum version.
	if tc.CheckVersions && pr.MinClientVersion != "" {
		if err := utils.CheckVersion(teleport.Version, pr.MinClientVersion); err != nil && trace.IsBadParameter(err) {
			fmt.Fprintf(tc.Config.Stderr, `
			WARNING
			Detected potentially incompatible client and server versions.
			Minimum client version supported by the server is %v but you are using %v.
			Please upgrade tsh to %v or newer or use the --skip-version-check flag to bypass this check.
			Future versions of tsh will fail when incompatible versions are detected.
			`, pr.MinClientVersion, teleport.Version, pr.MinClientVersion)
		}
	}

	// Update tc with proxy settings specified in Ping response.
	if err := tc.applyProxySettings(pr.Proxy); err != nil {
		return nil, trace.Wrap(err)
	}

	tc.lastPing = pr

	return pr, nil
}

// ShowMOTD fetches the cluster MotD, displays it (if any) and waits for
// confirmation from the user.
func (tc *TeleportClient) ShowMOTD(ctx context.Context) error {
	motd, err := webclient.GetMOTD(
		&webclient.Config{
			Context:      ctx,
			ProxyAddr:    tc.WebProxyAddr,
			Insecure:     tc.InsecureSkipVerify,
			Pool:         loopbackPool(tc.WebProxyAddr),
			ExtraHeaders: tc.ExtraProxyHeaders,
		})
	if err != nil {
		return trace.Wrap(err)
	}

	if motd.Text != "" {
		fmt.Fprintf(tc.Config.Stderr, "%s\nPress [ENTER] to continue.\n", motd.Text)
		// We're re-using the password reader for user acknowledgment for
		// aesthetic purposes, because we want to hide any garbage the
		// use might enter at the prompt. Whatever the user enters will
		// be simply discarded, and the user can still CTRL+C out if they
		// disagree.
		_, err := prompt.Stdin().ReadPassword(context.Background())
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// applyProxySettings updates configuration changes based on the advertised
// proxy settings, overriding existing fields in tc.
func (tc *TeleportClient) applyProxySettings(proxySettings webclient.ProxySettings) error {
	// Read in settings for HTTP endpoint of the proxy.
	if proxySettings.SSH.PublicAddr != "" {
		addr, err := utils.ParseAddr(proxySettings.SSH.PublicAddr)
		if err != nil {
			return trace.BadParameter(
				"failed to parse value received from the server: %q, contact your administrator for help",
				proxySettings.SSH.PublicAddr)
		}
		tc.WebProxyAddr = net.JoinHostPort(addr.Host(), strconv.Itoa(addr.Port(defaults.HTTPListenPort)))

		if tc.localAgent != nil {
			// Update local agent (that reads/writes to ~/.tsh) with the new address
			// of the web proxy. This will control where the keys are stored on disk
			// after login.
			tc.localAgent.UpdateProxyHost(addr.Host())
		}
	}
	// Read in settings for the SSH endpoint of the proxy.
	//
	// If listen_addr is set, take host from ProxyWebHost and port from what
	// was set. This is to maintain backward compatibility when Teleport only
	// supported public_addr.
	if proxySettings.SSH.ListenAddr != "" {
		addr, err := utils.ParseAddr(proxySettings.SSH.ListenAddr)
		if err != nil {
			return trace.BadParameter(
				"failed to parse value received from the server: %q, contact your administrator for help",
				proxySettings.SSH.ListenAddr)
		}
		webProxyHost, _ := tc.WebProxyHostPort()
		tc.SSHProxyAddr = net.JoinHostPort(webProxyHost, strconv.Itoa(addr.Port(defaults.SSHProxyListenPort)))
	}
	// If ssh_public_addr is set, override settings from listen_addr.
	if proxySettings.SSH.SSHPublicAddr != "" {
		addr, err := utils.ParseAddr(proxySettings.SSH.SSHPublicAddr)
		if err != nil {
			return trace.BadParameter(
				"failed to parse value received from the server: %q, contact your administrator for help",
				proxySettings.SSH.SSHPublicAddr)
		}
		tc.SSHProxyAddr = net.JoinHostPort(addr.Host(), strconv.Itoa(addr.Port(defaults.SSHProxyListenPort)))
	}

	return nil
}

// AddTrustedCA adds a new CA as trusted CA for this client, used in tests
func (tc *TeleportClient) AddTrustedCA(ctx context.Context, ca types.CertAuthority) error {
	if tc.localAgent == nil {
		return trace.BadParameter("TeleportClient.AddTrustedCA called on a client without localAgent")
	}
	err := tc.localAgent.AddHostSignersToCache(auth.AuthoritiesToTrustedCerts([]types.CertAuthority{ca}))
	if err != nil {
		return trace.Wrap(err)
	}

	// only host CA has TLS certificates, user CA will overwrite trusted certs
	// to empty file if called
	if ca.GetType() == types.HostCA {
		err = tc.localAgent.SaveTrustedCerts(auth.AuthoritiesToTrustedCerts([]types.CertAuthority{ca}))
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// AddKey adds a key to the client's local agent, used in tests.
func (tc *TeleportClient) AddKey(key *Key) error {
	if tc.localAgent == nil {
		return trace.BadParameter("TeleportClient.AddKey called on a client without localAgent")
	}
	if key.ClusterName == "" {
		key.ClusterName = tc.SiteName
	}
	return tc.localAgent.AddKey(key)
}

// SendEvent adds a events.EventFields to the channel.
func (tc *TeleportClient) SendEvent(ctx context.Context, e events.EventFields) error {
	// Try and send the event to the eventsCh. If blocking, keep blocking until
	// the passed in context in canceled.
	select {
	case tc.eventsCh <- e:
		return nil
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	}
}

// EventsChannel returns a channel that can be used to listen for events that
// occur for this session.
func (tc *TeleportClient) EventsChannel() <-chan events.EventFields {
	return tc.eventsCh
}

// loopbackPool reads trusted CAs if it finds it in a predefined location
// and will work only if target proxy address is loopback
func loopbackPool(proxyAddr string) *x509.CertPool {
	if !apiutils.IsLoopback(proxyAddr) {
		log.Debugf("not using loopback pool for remote proxy addr: %v", proxyAddr)
		return nil
	}
	log.Debugf("attempting to use loopback pool for local proxy addr: %v", proxyAddr)
	certPool, err := x509.SystemCertPool()
	if err != nil {
		log.Debugf("could not open system cert pool, using empty cert pool instead: %v", err)
		certPool = x509.NewCertPool()
	}

	certPath := filepath.Join(defaults.DataDir, defaults.SelfSignedCertPath)
	log.Debugf("reading self-signed certs from: %v", certPath)

	pemByte, err := os.ReadFile(certPath)
	if err != nil {
		log.Debugf("could not open any path in: %v", certPath)
		return nil
	}

	for {
		var block *pem.Block
		block, pemByte = pem.Decode(pemByte)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Debugf("could not parse cert in: %v, err: %v", certPath, err)
			return nil
		}
		certPool.AddCert(cert)
	}
	log.Debugf("using local pool for loopback proxy: %v, err: %v", certPath, err)
	return certPool
}

// connectToSSHAgent connects to the system SSH agent and returns an agent.Agent.
func connectToSSHAgent() agent.Agent {
	socketPath := os.Getenv(teleport.SSHAuthSock)
	conn, err := agentconn.Dial(socketPath)
	if err != nil {
		log.Errorf("[KEY AGENT] Unable to connect to SSH agent on socket: %q.", socketPath)
		return nil
	}

	log.Infof("[KEY AGENT] Connected to the system agent: %q", socketPath)
	return agent.NewClient(conn)
}

// Username returns the current user's username
func Username() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", trace.Wrap(err)
	}

	username := u.Username

	// If on Windows, strip the domain name.
	if runtime.GOOS == constants.WindowsOS {
		idx := strings.LastIndex(username, "\\")
		if idx > -1 {
			username = username[idx+1:]
		}
	}

	return username, nil
}

// AskOTP prompts the user to enter the OTP token.
func (tc *TeleportClient) AskOTP(ctx context.Context) (token string, err error) {
	return prompt.Password(ctx, tc.Stderr, prompt.Stdin(), "Enter your OTP token")
}

// AskPassword prompts the user to enter the password
func (tc *TeleportClient) AskPassword(ctx context.Context) (pwd string, err error) {
	return prompt.Password(
		ctx, tc.Stderr, prompt.Stdin(), fmt.Sprintf("Enter password for Teleport user %v", tc.Config.Username))
}

// loadTLS returns the user's TLS configuration for an external identity if the SkipLocalAuth flag was set
// or teleport core TLS certificate for the local agent.
func (tc *TeleportClient) loadTLSConfig() (*tls.Config, error) {
	// if SkipLocalAuth flag is set use an external identity file instead of loading cert from the local agent.
	if tc.SkipLocalAuth {
		return tc.TLS.Clone(), nil
	}

	tlsKey, err := tc.localAgent.GetCoreKey()
	if err != nil {
		return nil, trace.Wrap(err, "failed to fetch TLS key for %v", tc.Username)
	}

	rootCluster, err := tlsKey.RootClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	clusters := []string{rootCluster}
	if tc.SiteName != "" && rootCluster != tc.SiteName {
		clusters = append(clusters, tc.SiteName)
	}

	tlsConfig, err := tlsKey.TeleportClientTLSConfig(nil, clusters)
	if err != nil {
		return nil, trace.Wrap(err, "failed to generate client TLS config")
	}
	return tlsConfig, nil
}

// ParseLabelSpec parses a string like 'name=value,"long name"="quoted value"` into a map like
// { "name" -> "value", "long name" -> "quoted value" }
func ParseLabelSpec(spec string) (map[string]string, error) {
	var tokens []string
	openQuotes := false
	var tokenStart, assignCount int
	specLen := len(spec)
	// tokenize the label spec:
	for i, ch := range spec {
		endOfToken := false
		// end of line?
		if i+utf8.RuneLen(ch) == specLen {
			i += utf8.RuneLen(ch)
			endOfToken = true
		}
		switch ch {
		case '"':
			openQuotes = !openQuotes
		case '=', ',', ';':
			if !openQuotes {
				endOfToken = true
				if ch == '=' {
					assignCount++
				}
			}
		}
		if endOfToken && i > tokenStart {
			tokens = append(tokens, strings.TrimSpace(strings.Trim(spec[tokenStart:i], `"`)))
			tokenStart = i + 1
		}
	}
	// simple validation of tokenization: must have an even number of tokens (because they're pairs)
	// and the number of such pairs must be equal the number of assignments
	if len(tokens)%2 != 0 || assignCount != len(tokens)/2 {
		return nil, fmt.Errorf("invalid label spec: '%s', should be 'key=value'", spec)
	}
	// break tokens in pairs and put into a map:
	labels := make(map[string]string)
	for i := 0; i < len(tokens); i += 2 {
		labels[tokens[i]] = tokens[i+1]
	}
	return labels, nil
}

// ParseSearchKeywords parses a string ie: foo,bar,"quoted value"` into a slice of
// strings: ["foo", "bar", "quoted value"].
// Almost a replica to ParseLabelSpec, but with few modifications such as
// allowing a custom delimiter. Defaults to comma delimiter if not defined.
func ParseSearchKeywords(spec string, customDelimiter rune) []string {
	delimiter := customDelimiter
	if delimiter == 0 {
		delimiter = rune(',')
	}

	var tokens []string
	openQuotes := false
	var tokenStart int
	specLen := len(spec)
	// tokenize the label search:
	for i, ch := range spec {
		endOfToken := false
		if i+utf8.RuneLen(ch) == specLen {
			i += utf8.RuneLen(ch)
			endOfToken = true
		}
		switch ch {
		case '"':
			openQuotes = !openQuotes
		case delimiter:
			if !openQuotes {
				endOfToken = true
			}
		}
		if endOfToken && i > tokenStart {
			tokens = append(tokens, strings.TrimSpace(strings.Trim(spec[tokenStart:i], `"`)))
			tokenStart = i + 1
		}
	}

	return tokens
}

// Executes the given command on the client machine (localhost). If no command is given,
// executes shell
func runLocalCommand(command []string) error {
	if len(command) == 0 {
		user, err := user.Current()
		if err != nil {
			return trace.Wrap(err)
		}
		shell, err := shell.GetLoginShell(user.Username)
		if err != nil {
			return trace.Wrap(err)
		}
		command = []string{shell}
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

// String returns the same string spec which can be parsed by ParsePortForwardSpec.
func (fp ForwardedPorts) String() (retval []string) {
	for _, p := range fp {
		retval = append(retval, p.ToString())
	}
	return retval
}

// ParsePortForwardSpec parses parameter to -L flag, i.e. strings like "[ip]:80:remote.host:3000"
// The opposite of this function (spec generation) is ForwardedPorts.String()
func ParsePortForwardSpec(spec []string) (ports ForwardedPorts, err error) {
	if len(spec) == 0 {
		return ports, nil
	}
	const errTemplate = "Invalid port forwarding spec: '%s'. Could be like `80:remote.host:80`"
	ports = make([]ForwardedPort, len(spec))

	for i, str := range spec {
		parts := strings.Split(str, ":")
		if len(parts) < 3 || len(parts) > 4 {
			return nil, fmt.Errorf(errTemplate, str)
		}
		if len(parts) == 3 {
			parts = append([]string{"127.0.0.1"}, parts...)
		}
		p := &ports[i]
		p.SrcIP = parts[0]
		p.SrcPort, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf(errTemplate, str)
		}
		p.DestHost = parts[2]
		p.DestPort, err = strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf(errTemplate, str)
		}
	}
	return ports, nil
}

// String returns the same string spec which can be parsed by
// ParseDynamicPortForwardSpec.
func (fp DynamicForwardedPorts) String() (retval []string) {
	for _, p := range fp {
		retval = append(retval, p.ToString())
	}
	return retval
}

// ParseDynamicPortForwardSpec parses the dynamic port forwarding spec
// passed in the -D flag. The format of the dynamic port forwarding spec
// is [bind_address:]port.
func ParseDynamicPortForwardSpec(spec []string) (DynamicForwardedPorts, error) {
	result := make(DynamicForwardedPorts, 0, len(spec))

	for _, str := range spec {
		// Check whether this is only the port number, like "1080".
		// net.SplitHostPort would fail on that unless there's a colon in
		// front.
		if !strings.Contains(str, ":") {
			str = ":" + str
		}
		host, port, err := net.SplitHostPort(str)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// If no host is provided, bind to localhost.
		if host == "" {
			host = defaults.Localhost
		}

		srcPort, err := strconv.Atoi(port)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		result = append(result, DynamicForwardedPort{
			SrcIP:   host,
			SrcPort: srcPort,
		})
	}

	return result, nil
}

// InsecureSkipHostKeyChecking is used when the user passes in
// "StrictHostKeyChecking yes".
func InsecureSkipHostKeyChecking(host string, remote net.Addr, key ssh.PublicKey) error {
	return nil
}

// isFIPS returns if the binary was build with BoringCrypto, which implies
// FedRAMP/FIPS 140-2 mode for tsh.
func isFIPS() bool {
	return modules.GetModules().IsBoringBinary()
}

// playSession plays session in the terminal
func playSession(sessionEvents []events.EventFields, stream []byte) error {
	term, err := terminal.New(nil, nil, nil)
	if err != nil {
		return trace.Wrap(err)
	}

	defer term.Close()

	// configure terminal for direct unbuffered echo-less input:
	if term.IsAttached() {
		err := term.InitRaw(true)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	player := newSessionPlayer(sessionEvents, stream, term)
	errorCh := make(chan error)
	// keys:
	const (
		keyCtrlC = 3
		keyCtrlD = 4
		keySpace = 32
		keyLeft  = 68
		keyRight = 67
		keyUp    = 65
		keyDown  = 66
	)
	// playback control goroutine
	go func() {
		defer player.EndPlayback()
		var key [1]byte
		for {
			_, err := term.Stdin().Read(key[:])
			if err != nil {
				errorCh <- err
				return
			}
			switch key[0] {
			// Ctrl+C or Ctrl+D
			case keyCtrlC, keyCtrlD:
				return
			// Space key
			case keySpace:
				player.TogglePause()
			// <- arrow
			case keyLeft, keyDown:
				player.Rewind()
			// -> arrow
			case keyRight, keyUp:
				player.Forward()
			}
		}
	}()
	// player starts playing in its own goroutine
	player.Play()
	// wait for keypresses loop to end
	select {
	case <-player.stopC:
		fmt.Println("\n\nend of session playback")
		return nil
	case err := <-errorCh:
		return trace.Wrap(err)
	}
}
