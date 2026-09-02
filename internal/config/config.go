package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	defaultCommandTimeoutMS  = 60_000
	defaultConnectTimeoutMS  = 20_000
	defaultTransferTimeoutMS = 60_000
	defaultMaxChars          = 5_000
	defaultMaxOutputBytes    = 1_048_576
	defaultMaxTransferBytes  = 10 * 1_048_576
	defaultMaxRequestBytes   = 16 * 1_048_576
	defaultJobRetentionMS    = 24 * 60 * 60 * 1000
	defaultMaxJobs           = 100
)

// Config is the complete ssh-mcp configuration.
type Config struct {
	Defaults Defaults  `toml:"defaults"`
	HTTP     HTTP      `toml:"http"`
	Profiles []Profile `toml:"profiles"`
}

// Defaults controls server-wide behavior. Individual profiles can override
// command limits where a pointer field is provided on Profile.
type Defaults struct {
	DefaultProfile    string   `toml:"defaultProfile"`
	CommandTimeoutMS  int      `toml:"commandTimeoutMs"`
	ConnectTimeoutMS  int      `toml:"connectTimeoutMs"`
	TransferTimeoutMS int      `toml:"transferTimeoutMs"`
	CommandMaxChars   int      `toml:"commandMaxChars"`
	MaxOutputBytes    int      `toml:"commandMaxOutputBytes"`
	MaxTransferBytes  int64    `toml:"maxTransferBytes"`
	HostKeyMode       string   `toml:"hostKeyMode"`
	KnownHostsFile    string   `toml:"knownHostsFile"`
	DenyCommands      []string `toml:"denyCommands"`
	ApprovalMode      string   `toml:"approvalMode"`
	AuditLog          string   `toml:"auditLog"`
	AuditRedact       []string `toml:"auditRedact"`
	SSHConfigFile     string   `toml:"sshConfigFile"`
	ImportSSHHosts    []string `toml:"importSSHHosts"`
	JobRetentionMS    int      `toml:"jobRetentionMs"`
	MaxJobs           int      `toml:"maxJobs"`
	JobStateFile      string   `toml:"jobStateFile"`
}

// HTTP configures the optional Streamable HTTP transport. A bearer token is
// always resolved from TokenEnv; it is never stored in this file.
type HTTP struct {
	Enabled              bool     `toml:"enabled"`
	Listen               string   `toml:"listen"`
	Path                 string   `toml:"path"`
	AuthMode             string   `toml:"authMode"`
	TokenEnv             string   `toml:"tokenEnv"`
	TLSCertFile          string   `toml:"tlsCertFile"`
	TLSKeyFile           string   `toml:"tlsKeyFile"`
	AllowedOrigins       []string `toml:"allowedOrigins"`
	ResourceURL          string   `toml:"resourceUrl"`
	AuthorizationServers []string `toml:"authorizationServers"`
	IntrospectionURL     string   `toml:"introspectionUrl"`
	OAuthClientIDEnv     string   `toml:"oauthClientIdEnv"`
	OAuthClientSecretEnv string   `toml:"oauthClientSecretEnv"`
	RequiredScopes       []string `toml:"requiredScopes"`
	Audience             string   `toml:"audience"`
	MaxRequestBytes      int64    `toml:"maxRequestBytes"`
}

// Profile describes one SSH target. Passwords and key passphrases are always
// resolved from environment variables and never accepted in this structure.
type Profile struct {
	Name                      string            `toml:"name"`
	Host                      string            `toml:"host"`
	Port                      int               `toml:"port"`
	User                      string            `toml:"user"`
	Auth                      string            `toml:"auth"`
	KeyRef                    string            `toml:"keyRef"`
	SSHConfigHost             string            `toml:"sshConfigHost"`
	ProxyJump                 string            `toml:"proxyJump"`
	AgentKeyFingerprint       string            `toml:"agentKeyFingerprint"`
	Workdir                   string            `toml:"workdir"`
	TrustedHostKey            string            `toml:"trustedHostKey"`
	KnownHostsFile            string            `toml:"knownHostsFile"`
	TTY                       bool              `toml:"tty"`
	ReadOnly                  bool              `toml:"readOnly"`
	AllowRoot                 bool              `toml:"allowRoot"`
	AllowUnrestrictedCommands bool              `toml:"allowUnrestrictedCommands"`
	AllowedCommands           []string          `toml:"allowedCommands"`
	DenyCommands              []string          `toml:"denyCommands"`
	ApprovalMode              string            `toml:"approvalMode"`
	CommandTemplates          []CommandTemplate `toml:"commandTemplates"`
	CommandTimeoutMS          *int              `toml:"commandTimeoutMs"`
	TransferTimeoutMS         *int              `toml:"transferTimeoutMs"`
	CommandMaxChars           *int              `toml:"commandMaxChars"`
	MaxOutputBytes            *int              `toml:"commandMaxOutputBytes"`
	MaxTransferBytes          *int64            `toml:"maxTransferBytes"`
	InsecureSkipHostKey       bool              `toml:"insecureSkipHostKey"`
	JumpOnly                  bool              `toml:"jumpOnly"`
}

// CommandTemplate exposes a named, parameterized operation. Placeholders use
// {{name}} syntax and are always POSIX-shell quoted before substitution.
type CommandTemplate struct {
	Name             string   `toml:"name"`
	Description      string   `toml:"description"`
	Command          string   `toml:"command"`
	Parameters       []string `toml:"parameters"`
	ReadOnly         bool     `toml:"readOnly"`
	RequiresApproval bool     `toml:"requiresApproval"`
}

// DefaultPath returns the platform-specific default config path.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(dir, "ssh-mcp", "config.toml"), nil
}

// Load parses a TOML configuration, rejects unknown keys, and validates it.
func Load(path string) (*Config, error) {
	path, err := ExpandPath(path)
	if err != nil {
		return nil, err
	}
	if err := checkPermissions(path); err != nil {
		return nil, err
	}

	cfg := &Config{Defaults: defaultDefaults(), HTTP: defaultHTTP()}
	metadata, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return nil, fmt.Errorf("unknown config keys: %s", strings.Join(keys, ", "))
	}
	if cfg.Defaults.JobStateFile == "" {
		cfg.Defaults.JobStateFile = filepath.Join(filepath.Dir(path), "jobs.json")
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Empty returns a valid unconfigured configuration. It allows MCP clients to
// initialize and inspect tools before a config file has been created.
func Empty() *Config {
	return &Config{Defaults: defaultDefaults(), HTTP: defaultHTTP()}
}

func defaultDefaults() Defaults {
	return Defaults{
		CommandTimeoutMS:  defaultCommandTimeoutMS,
		ConnectTimeoutMS:  defaultConnectTimeoutMS,
		TransferTimeoutMS: defaultTransferTimeoutMS,
		CommandMaxChars:   defaultMaxChars,
		MaxOutputBytes:    defaultMaxOutputBytes,
		MaxTransferBytes:  defaultMaxTransferBytes,
		HostKeyMode:       "strict",
		KnownHostsFile:    "~/.ssh/known_hosts",
		ApprovalMode:      "risky",
		SSHConfigFile:     "~/.ssh/config",
		JobRetentionMS:    defaultJobRetentionMS,
		MaxJobs:           defaultMaxJobs,
	}
}

func (c *Config) normalizeAndValidate() error {
	if c.Defaults.CommandTimeoutMS <= 0 {
		return errors.New("defaults.commandTimeoutMs must be positive")
	}
	if c.Defaults.ConnectTimeoutMS <= 0 {
		return errors.New("defaults.connectTimeoutMs must be positive")
	}
	if c.Defaults.TransferTimeoutMS <= 0 {
		return errors.New("defaults.transferTimeoutMs must be positive")
	}
	if c.Defaults.CommandMaxChars < 0 {
		return errors.New("defaults.commandMaxChars cannot be negative")
	}
	if c.Defaults.MaxOutputBytes <= 0 {
		return errors.New("defaults.commandMaxOutputBytes must be positive")
	}
	if c.Defaults.MaxTransferBytes <= 0 {
		return errors.New("defaults.maxTransferBytes must be positive")
	}
	if c.Defaults.JobRetentionMS <= 0 {
		return errors.New("defaults.jobRetentionMs must be positive")
	}
	if c.Defaults.MaxJobs <= 0 {
		return errors.New("defaults.maxJobs must be positive")
	}
	if err := validateApprovalMode("defaults.approvalMode", c.Defaults.ApprovalMode); err != nil {
		return err
	}
	if c.Defaults.HostKeyMode == "" {
		c.Defaults.HostKeyMode = "strict"
	}
	if c.Defaults.HostKeyMode != "strict" && c.Defaults.HostKeyMode != "insecure" {
		return fmt.Errorf("defaults.hostKeyMode must be strict or insecure, got %q", c.Defaults.HostKeyMode)
	}
	if c.Defaults.KnownHostsFile != "" {
		var err error
		c.Defaults.KnownHostsFile, err = ExpandPath(c.Defaults.KnownHostsFile)
		if err != nil {
			return fmt.Errorf("defaults.knownHostsFile: %w", err)
		}
	}
	if c.Defaults.SSHConfigFile != "" {
		var err error
		c.Defaults.SSHConfigFile, err = ExpandPath(c.Defaults.SSHConfigFile)
		if err != nil {
			return fmt.Errorf("defaults.sshConfigFile: %w", err)
		}
	}
	if c.Defaults.AuditLog != "" {
		var err error
		c.Defaults.AuditLog, err = ExpandPath(c.Defaults.AuditLog)
		if err != nil {
			return fmt.Errorf("defaults.auditLog: %w", err)
		}
	}
	if c.Defaults.JobStateFile != "" {
		var err error
		c.Defaults.JobStateFile, err = ExpandPath(c.Defaults.JobStateFile)
		if err != nil {
			return fmt.Errorf("defaults.jobStateFile: %w", err)
		}
	}
	if err := c.applyOpenSSHConfig(); err != nil {
		return err
	}
	if err := c.normalizeHTTP(); err != nil {
		return err
	}

	names := make(map[string]struct{}, len(c.Profiles))
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if p.Name == "" || p.Host == "" || p.User == "" {
			return fmt.Errorf("profiles[%d]: name, host, and user are required", i)
		}
		if p.User == "root" && !p.AllowRoot {
			return fmt.Errorf("profile %q: root SSH access requires allowRoot=true", p.Name)
		}
		if _, exists := names[p.Name]; exists {
			return fmt.Errorf("duplicate profile name %q", p.Name)
		}
		names[p.Name] = struct{}{}
		if p.Port == 0 {
			p.Port = 22
		}
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("profile %q: port must be between 1 and 65535", p.Name)
		}
		if p.Auth == "" {
			p.Auth = "agent"
		}
		switch p.Auth {
		case "agent", "key", "password":
		default:
			return fmt.Errorf("profile %q: auth must be agent, key, or password", p.Name)
		}
		if p.Auth == "key" && p.KeyRef == "" {
			return fmt.Errorf("profile %q: keyRef is required for key authentication", p.Name)
		}
		if p.AgentKeyFingerprint != "" && p.Auth != "agent" {
			return fmt.Errorf("profile %q: agentKeyFingerprint requires auth=agent", p.Name)
		}
		if p.AgentKeyFingerprint != "" && !strings.HasPrefix(p.AgentKeyFingerprint, "SHA256:") {
			return fmt.Errorf("profile %q: agentKeyFingerprint must be an SHA256 fingerprint", p.Name)
		}
		if err := validateApprovalMode(fmt.Sprintf("profile %q approvalMode", p.Name), p.ApprovalMode); err != nil {
			return err
		}
		if err := validateTemplates(p); err != nil {
			return err
		}
		if p.KeyRef != "" {
			var err error
			p.KeyRef, err = ExpandPath(p.KeyRef)
			if err != nil {
				return fmt.Errorf("profile %q keyRef: %w", p.Name, err)
			}
		}
		if p.KnownHostsFile != "" {
			var err error
			p.KnownHostsFile, err = ExpandPath(p.KnownHostsFile)
			if err != nil {
				return fmt.Errorf("profile %q knownHostsFile: %w", p.Name, err)
			}
		}
		if p.InsecureSkipHostKey && p.TrustedHostKey != "" {
			return fmt.Errorf("profile %q: insecureSkipHostKey and trustedHostKey cannot both be set", p.Name)
		}
		if err := validatePositiveOverride(p.Name, "commandTimeoutMs", p.CommandTimeoutMS, false); err != nil {
			return err
		}
		if err := validatePositiveOverride(p.Name, "transferTimeoutMs", p.TransferTimeoutMS, false); err != nil {
			return err
		}
		if err := validatePositiveOverride(p.Name, "commandMaxChars", p.CommandMaxChars, true); err != nil {
			return err
		}
		if err := validatePositiveOverride(p.Name, "commandMaxOutputBytes", p.MaxOutputBytes, false); err != nil {
			return err
		}
		if p.MaxTransferBytes != nil && *p.MaxTransferBytes <= 0 {
			return fmt.Errorf("profile %q: maxTransferBytes must be positive", p.Name)
		}
	}
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if p.ProxyJump != "" {
			_, ok := names[p.ProxyJump]
			if !ok {
				return fmt.Errorf("profile %q: proxyJump %q does not name another profile", p.Name, p.ProxyJump)
			}
		}
	}
	if err := c.validateProxyJumpCycles(); err != nil {
		return err
	}

	if c.Defaults.DefaultProfile == "" {
		var usable []string
		for i := range c.Profiles {
			if !c.Profiles[i].JumpOnly {
				usable = append(usable, c.Profiles[i].Name)
			}
		}
		if len(usable) == 1 {
			c.Defaults.DefaultProfile = usable[0]
		}
	}
	if c.Defaults.DefaultProfile != "" {
		if _, ok := names[c.Defaults.DefaultProfile]; !ok {
			return fmt.Errorf("defaults.defaultProfile %q does not name a profile", c.Defaults.DefaultProfile)
		}
		for i := range c.Profiles {
			if c.Profiles[i].Name == c.Defaults.DefaultProfile && c.Profiles[i].JumpOnly {
				return fmt.Errorf("defaults.defaultProfile %q is jump-only", c.Defaults.DefaultProfile)
			}
		}
	}
	return nil
}

func validateApprovalMode(field, mode string) error {
	if mode == "" || mode == "never" || mode == "risky" || mode == "always" {
		return nil
	}
	return fmt.Errorf("%s must be never, risky, or always, got %q", field, mode)
}

func (c *Config) normalizeHTTP() error {
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = "127.0.0.1:8080"
	}
	if c.HTTP.Path == "" {
		c.HTTP.Path = "/mcp"
	}
	if !strings.HasPrefix(c.HTTP.Path, "/") || strings.ContainsAny(c.HTTP.Path, "{}?#\x00") {
		return errors.New("http.path must be a literal URL path starting with / and contain no wildcard, query, fragment, or NUL characters")
	}
	if c.HTTP.TokenEnv == "" {
		c.HTTP.TokenEnv = "SSH_MCP_HTTP_TOKEN"
	}
	if c.HTTP.AuthMode == "" {
		c.HTTP.AuthMode = "token"
	}
	if c.HTTP.AuthMode != "token" && c.HTTP.AuthMode != "oauth" {
		return fmt.Errorf("http.authMode must be token or oauth, got %q", c.HTTP.AuthMode)
	}
	if c.HTTP.MaxRequestBytes == 0 {
		c.HTTP.MaxRequestBytes = defaultMaxRequestBytes
	}
	if c.HTTP.MaxRequestBytes < 1024 {
		return errors.New("http.maxRequestBytes must be at least 1024")
	}
	if c.HTTP.Enabled && c.HTTP.AuthMode == "token" && os.Getenv(c.HTTP.TokenEnv) == "" {
		return fmt.Errorf("http.enabled with authMode=token requires bearer token environment variable %s", c.HTTP.TokenEnv)
	}
	if c.HTTP.OAuthClientIDEnv == "" {
		c.HTTP.OAuthClientIDEnv = "SSH_MCP_OAUTH_CLIENT_ID"
	}
	if c.HTTP.OAuthClientSecretEnv == "" {
		c.HTTP.OAuthClientSecretEnv = "SSH_MCP_OAUTH_CLIENT_SECRET"
	}
	if c.HTTP.Enabled && c.HTTP.AuthMode == "oauth" {
		if c.HTTP.ResourceURL == "" || c.HTTP.IntrospectionURL == "" || len(c.HTTP.AuthorizationServers) == 0 {
			return errors.New("http.authMode=oauth requires resourceUrl, introspectionUrl, and authorizationServers")
		}
		if os.Getenv(c.HTTP.OAuthClientIDEnv) == "" || os.Getenv(c.HTTP.OAuthClientSecretEnv) == "" {
			return fmt.Errorf("http.authMode=oauth requires %s and %s", c.HTTP.OAuthClientIDEnv, c.HTTP.OAuthClientSecretEnv)
		}
		for field, raw := range map[string]string{"resourceUrl": c.HTTP.ResourceURL, "introspectionUrl": c.HTTP.IntrospectionURL} {
			parsed, err := url.Parse(raw)
			if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("http.%s must be an absolute HTTPS URL", field)
			}
		}
		for _, raw := range c.HTTP.AuthorizationServers {
			parsed, err := url.Parse(raw)
			if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("http.authorizationServers entry %q must be an absolute HTTPS URL", raw)
			}
		}
		for _, scope := range c.HTTP.RequiredScopes {
			if !validOAuthScope(scope) {
				return fmt.Errorf("http.requiredScopes entry %q is not a valid OAuth scope token", scope)
			}
		}
	}
	for _, raw := range c.HTTP.AllowedOrigins {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return fmt.Errorf("http.allowedOrigins entry %q must be an HTTP(S) origin without path, query, fragment, or user information", raw)
		}
	}
	if (c.HTTP.TLSCertFile == "") != (c.HTTP.TLSKeyFile == "") {
		return errors.New("http.tlsCertFile and http.tlsKeyFile must be set together")
	}
	for field, value := range map[string]*string{"tlsCertFile": &c.HTTP.TLSCertFile, "tlsKeyFile": &c.HTTP.TLSKeyFile} {
		if *value != "" {
			path, err := ExpandPath(*value)
			if err != nil {
				return fmt.Errorf("http.%s: %w", field, err)
			}
			*value = path
		}
	}
	if c.HTTP.Enabled {
		host, _, err := net.SplitHostPort(c.HTTP.Listen)
		if err != nil {
			return fmt.Errorf("http.listen must be host:port: %w", err)
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		localhost := host == "localhost" || (ip != nil && ip.IsLoopback())
		if !localhost && c.HTTP.TLSCertFile == "" {
			return errors.New("HTTP listening on a non-loopback address requires TLS")
		}
	}
	return nil
}

func (c *Config) ApprovalMode(p *Profile) string {
	if p.ApprovalMode != "" {
		return p.ApprovalMode
	}
	return c.Defaults.ApprovalMode
}

func validatePositiveOverride(profile, field string, value *int, zeroAllowed bool) error {
	if value == nil || *value > 0 || (zeroAllowed && *value == 0) {
		return nil
	}
	return fmt.Errorf("profile %q: %s must be positive", profile, field)
}

// Profile returns the named profile, or the configured default when name is empty.
func (c *Config) Profile(name string) (*Profile, error) {
	if len(c.Profiles) == 0 {
		return nil, errors.New("ssh-mcp is not configured; create the config file and add at least one [[profiles]] entry")
	}
	if name == "" {
		name = c.Defaults.DefaultProfile
		if name == "" {
			return nil, errors.New("profile is required because defaults.defaultProfile is not set")
		}
	}
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			if c.Profiles[i].JumpOnly {
				return nil, fmt.Errorf("SSH profile %q is jump-only and cannot be targeted by tools", name)
			}
			return &c.Profiles[i], nil
		}
	}
	return nil, fmt.Errorf("unknown SSH profile %q", name)
}

func (c *Config) CommandTimeout(p *Profile) int {
	if p.CommandTimeoutMS != nil {
		return *p.CommandTimeoutMS
	}
	return c.Defaults.CommandTimeoutMS
}

func (c *Config) CommandMaxChars(p *Profile) int {
	if p.CommandMaxChars != nil {
		return *p.CommandMaxChars
	}
	return c.Defaults.CommandMaxChars
}

func validOAuthScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, r := range scope {
		if r != 0x21 && (r < 0x23 || r > 0x5b) && (r < 0x5d || r > 0x7e) {
			return false
		}
	}
	return true
}

func defaultHTTP() HTTP {
	return HTTP{ //nolint:gosec // these are environment-variable names, not credentials
		Listen:               "127.0.0.1:8080",
		Path:                 "/mcp",
		AuthMode:             "token",
		TokenEnv:             "SSH_MCP_HTTP_TOKEN",
		OAuthClientIDEnv:     "SSH_MCP_OAUTH_CLIENT_ID",
		OAuthClientSecretEnv: "SSH_MCP_OAUTH_CLIENT_SECRET",
		MaxRequestBytes:      defaultMaxRequestBytes,
	}
}

func (c *Config) TransferTimeout(p *Profile) int {
	if p.TransferTimeoutMS != nil {
		return *p.TransferTimeoutMS
	}
	return c.Defaults.TransferTimeoutMS
}

func (c *Config) OutputLimit(p *Profile) int {
	if p.MaxOutputBytes != nil {
		return *p.MaxOutputBytes
	}
	return c.Defaults.MaxOutputBytes
}

func (c *Config) TransferLimit(p *Profile) int64 {
	if p.MaxTransferBytes != nil {
		return *p.MaxTransferBytes
	}
	return c.Defaults.MaxTransferBytes
}

func (c *Config) KnownHostsPath(p *Profile) string {
	if p.KnownHostsFile != "" {
		return p.KnownHostsFile
	}
	return c.Defaults.KnownHostsFile
}

func (c *Config) HostKeyInsecure(p *Profile) bool {
	return p.InsecureSkipHostKey || c.Defaults.HostKeyMode == "insecure"
}

// ExpandPath expands environment variables and a leading home-directory marker.
func ExpandPath(value string) (string, error) {
	value = os.ExpandEnv(value)
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find home directory: %w", err)
		}
		if value == "~" {
			value = home
		} else {
			value = filepath.Join(home, value[2:])
		}
	}
	return filepath.Clean(value), nil
}

func checkPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %q: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("config %q is accessible by group or others (mode %04o); run chmod 600", path, info.Mode().Perm())
	}
	return nil
}
