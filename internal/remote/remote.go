package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssh-mcp/internal/config"
)

// RunOptions controls one remote command invocation.
type RunOptions struct {
	TTY         bool
	DisableTTY  bool
	Stdin       string
	Timeout     time.Duration
	OutputLimit int
}

// CommandResult is returned even when the remote command exits unsuccessfully,
// allowing MCP clients to inspect stderr and the exit status.
type CommandResult struct {
	Profile    string `json:"profile"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exitCode"`
	DurationMS int64  `json:"durationMs"`
	Signal     string `json:"signal,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	TimedOut   bool   `json:"timedOut,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ConnectionInfo reports lazily-established connection state without exposing
// credentials or host-key material.
type ConnectionInfo struct {
	Profile      string     `json:"profile"`
	Address      string     `json:"address"`
	User         string     `json:"user"`
	Status       string     `json:"status"`
	ReadOnly     bool       `json:"readOnly"`
	JumpOnly     bool       `json:"jumpOnly,omitempty"`
	Active       int        `json:"activeChannels"`
	ConnectedAt  *time.Time `json:"connectedAt,omitempty"`
	LastActivity *time.Time `json:"lastActivity,omitempty"`
	ProxyJump    string     `json:"proxyJump,omitempty"`
}

// FileInfo is a portable subset of remote file metadata.
type FileInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	ModeBits  uint32    `json:"modeBits"`
	ModTime   time.Time `json:"modTime"`
	IsDir     bool      `json:"isDir"`
	IsSymlink bool      `json:"isSymlink"`
	IsRegular bool      `json:"isRegular"`
}

type AgentKeyInfo struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

type DiagnosticStep struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Message    string `json:"message"`
	DurationMS int64  `json:"durationMs"`
}

type DiagnosticResult struct {
	Profile          string           `json:"profile"`
	Address          string           `json:"address"`
	ProxyJump        string           `json:"proxyJump,omitempty"`
	Auth             string           `json:"auth"`
	AgentKeys        []AgentKeyInfo   `json:"agentKeys,omitempty"`
	SelectedAgentKey string           `json:"selectedAgentKey,omitempty"`
	ServerHostKey    string           `json:"serverHostKey,omitempty"`
	Steps            []DiagnosticStep `json:"steps"`
	Success          bool             `json:"success"`
}

// Backend is the interface used by the MCP tool layer. Keeping the network
// boundary behind an interface makes policy and protocol behavior testable
// without connecting to a real host.
type Backend interface {
	ListConnections() []ConnectionInfo
	Run(context.Context, *config.Profile, string, RunOptions) (CommandResult, error)
	Upload(context.Context, *config.Profile, string, []byte, os.FileMode) (int64, error)
	Download(context.Context, *config.Profile, string, int64) ([]byte, error)
	ReadRange(context.Context, *config.Profile, string, int64, int64) ([]byte, error)
	ListDirectory(context.Context, *config.Profile, string, int) ([]FileInfo, error)
	Stat(context.Context, *config.Profile, string) (FileInfo, error)
	Checksum(context.Context, *config.Profile, string, int64) (string, int64, error)
	Mkdir(context.Context, *config.Profile, string, os.FileMode, bool) error
	Rename(context.Context, *config.Profile, string, string, bool) error
	Remove(context.Context, *config.Profile, string) (FileInfo, error)
	Diagnose(context.Context, *config.Profile) DiagnosticResult
	Close() error
}

// Manager owns one reusable SSH connection per configured profile.
type Manager struct {
	cfg         *config.Config
	connections map[string]*connection
}

func NewManager(cfg *config.Config) *Manager {
	m := &Manager{cfg: cfg, connections: make(map[string]*connection, len(cfg.Profiles))}
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		m.connections[p.Name] = &connection{cfg: cfg, profile: p, manager: m}
	}
	return m
}

func (m *Manager) ListConnections() []ConnectionInfo {
	infos := make([]ConnectionInfo, 0, len(m.cfg.Profiles))
	for i := range m.cfg.Profiles {
		p := &m.cfg.Profiles[i]
		infos = append(infos, m.connections[p.Name].info())
	}
	return infos
}

func (m *Manager) Run(ctx context.Context, p *config.Profile, command string, opts RunOptions) (CommandResult, error) {
	c, err := m.connection(p)
	if err != nil {
		return CommandResult{}, err
	}
	return c.run(ctx, command, opts)
}

func (m *Manager) Upload(ctx context.Context, p *config.Profile, remotePath string, data []byte, mode os.FileMode) (int64, error) {
	c, err := m.connection(p)
	if err != nil {
		return 0, err
	}
	return c.upload(ctx, remotePath, data, mode)
}

func (m *Manager) Download(ctx context.Context, p *config.Profile, remotePath string, maxBytes int64) ([]byte, error) {
	c, err := m.connection(p)
	if err != nil {
		return nil, err
	}
	return c.download(ctx, remotePath, maxBytes)
}

func (m *Manager) ReadRange(ctx context.Context, p *config.Profile, remotePath string, offset, length int64) ([]byte, error) {
	c, err := m.connection(p)
	if err != nil {
		return nil, err
	}
	return c.readRange(ctx, remotePath, offset, length)
}

func (m *Manager) ListDirectory(ctx context.Context, p *config.Profile, remotePath string, maxEntries int) ([]FileInfo, error) {
	c, err := m.connection(p)
	if err != nil {
		return nil, err
	}
	return c.listDirectory(ctx, remotePath, maxEntries)
}

func (m *Manager) Stat(ctx context.Context, p *config.Profile, remotePath string) (FileInfo, error) {
	c, err := m.connection(p)
	if err != nil {
		return FileInfo{}, err
	}
	return c.stat(ctx, remotePath)
}

func (m *Manager) Checksum(ctx context.Context, p *config.Profile, remotePath string, maxBytes int64) (string, int64, error) {
	c, err := m.connection(p)
	if err != nil {
		return "", 0, err
	}
	return c.checksum(ctx, remotePath, maxBytes)
}

func (m *Manager) Mkdir(ctx context.Context, p *config.Profile, remotePath string, mode os.FileMode, parents bool) error {
	c, err := m.connection(p)
	if err != nil {
		return err
	}
	return c.mkdir(ctx, remotePath, mode, parents)
}

func (m *Manager) Rename(ctx context.Context, p *config.Profile, oldPath, newPath string, overwrite bool) error {
	c, err := m.connection(p)
	if err != nil {
		return err
	}
	return c.rename(ctx, oldPath, newPath, overwrite)
}

func (m *Manager) Remove(ctx context.Context, p *config.Profile, remotePath string) (FileInfo, error) {
	c, err := m.connection(p)
	if err != nil {
		return FileInfo{}, err
	}
	return c.remove(ctx, remotePath)
}

func (m *Manager) Diagnose(ctx context.Context, p *config.Profile) DiagnosticResult {
	c, err := m.connection(p)
	if err != nil {
		return DiagnosticResult{Profile: p.Name, Success: false, Steps: []DiagnosticStep{{Name: "configuration", Message: err.Error()}}}
	}
	return c.diagnose(ctx)
}

func (m *Manager) connection(p *config.Profile) (*connection, error) {
	c, ok := m.connections[p.Name]
	if !ok {
		return nil, fmt.Errorf("profile %q has no connection entry", p.Name)
	}
	return c, nil
}

func (m *Manager) Close() error {
	var errs []error
	for _, c := range m.connections {
		if err := c.close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type connection struct {
	cfg     *config.Config
	profile *config.Profile
	manager *Manager

	mu           sync.Mutex
	client       *ssh.Client
	active       int
	connectedAt  *time.Time
	lastActivity *time.Time
}

func (c *connection) info() ConnectionInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := "disconnected"
	if c.client != nil {
		status = "connected"
	}
	return ConnectionInfo{
		Profile:      c.profile.Name,
		Address:      net.JoinHostPort(c.profile.Host, fmt.Sprint(c.profile.Port)),
		User:         c.profile.User,
		Status:       status,
		ReadOnly:     c.profile.ReadOnly,
		JumpOnly:     c.profile.JumpOnly,
		Active:       c.active,
		ConnectedAt:  cloneTime(c.connectedAt),
		LastActivity: cloneTime(c.lastActivity),
		ProxyJump:    c.profile.ProxyJump,
	}
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	copy := *t
	return &copy
}

func (c *connection) getClient(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	client, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	c.client = client
	c.connectedAt = &now
	c.lastActivity = &now
	go c.watch(client)
	return client, nil
}

func (c *connection) watch(client *ssh.Client) {
	_ = client.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == client {
		c.client = nil
		c.connectedAt = nil
	}
}

func (c *connection) dial(ctx context.Context) (*ssh.Client, error) {
	return c.dialObserved(ctx, nil, nil)
}

func (c *connection) dialObserved(ctx context.Context, observed *string, hostKeyError *error) (*ssh.Client, error) {
	auth, cleanup, err := authMethods(ctx, c.profile)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	hostKeys, err := c.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	if observed != nil {
		verified := hostKeys
		hostKeys = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			*observed = ssh.FingerprintSHA256(key)
			err := verified(hostname, remote, key)
			if hostKeyError != nil {
				*hostKeyError = err
			}
			return err
		}
	}
	clientConfig := &ssh.ClientConfig{
		User:            c.profile.User,
		Auth:            auth,
		HostKeyCallback: hostKeys,
		Timeout:         time.Duration(c.cfg.Defaults.ConnectTimeoutMS) * time.Millisecond,
	}

	address := net.JoinHostPort(c.profile.Host, fmt.Sprint(c.profile.Port))
	raw, err := c.openTransport(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = raw.Close()
		}
	}()
	cancelHandshake := context.AfterFunc(ctx, func() { _ = raw.Close() })

	deadline := time.Now().Add(time.Duration(c.cfg.Defaults.ConnectTimeoutMS) * time.Millisecond)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	deadlineSet := raw.SetDeadline(deadline) == nil
	var deadlineTimer *time.Timer
	if !deadlineSet {
		deadlineTimer = time.AfterFunc(time.Until(deadline), func() { _ = raw.Close() })
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, address, clientConfig)
	stopped := cancelHandshake()
	if deadlineTimer != nil {
		deadlineTimer.Stop()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("SSH handshake with %s: %w", address, ctx.Err())
		}
		return nil, fmt.Errorf("SSH handshake with %s: %w", address, err)
	}
	if !stopped && ctx.Err() != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH handshake with %s: %w", address, ctx.Err())
	}
	if deadlineSet {
		if err := raw.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("clear SSH handshake deadline: %w", err)
		}
	}
	succeeded = true
	return ssh.NewClient(conn, channels, requests), nil
}

func (c *connection) openTransport(ctx context.Context, address string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Defaults.ConnectTimeoutMS)*time.Millisecond)
	defer cancel()
	dialer := &net.Dialer{Timeout: time.Duration(c.cfg.Defaults.ConnectTimeoutMS) * time.Millisecond}
	if c.profile.ProxyJump == "" {
		return dialer.DialContext(dialCtx, "tcp", address)
	}
	jump, ok := c.manager.connections[c.profile.ProxyJump]
	if !ok {
		return nil, fmt.Errorf("proxy jump profile %q is not configured", c.profile.ProxyJump)
	}
	jumpClient, err := jump.getClient(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("connect proxy jump %q: %w", c.profile.ProxyJump, err)
	}
	return dialThroughSSH(dialCtx, jumpClient, address)
}

func dialThroughSSH(ctx context.Context, client *ssh.Client, address string) (net.Conn, error) {
	return client.DialContext(ctx, "tcp", address)
}

func (c *connection) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if c.profile.TrustedHostKey != "" {
		want := strings.TrimSpace(c.profile.TrustedHostKey)
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if got != want {
				return fmt.Errorf("host key mismatch for %s: expected %s, received %s", hostname, want, got)
			}
			return nil
		}, nil
	}
	if c.cfg.HostKeyInsecure(c.profile) {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // only reachable through an explicit insecure configuration opt-in
	}
	knownHostsFile := c.cfg.KnownHostsPath(c.profile)
	if knownHostsFile == "" {
		return nil, fmt.Errorf("profile %q: strict host-key mode requires knownHostsFile or trustedHostKey", c.profile.Name)
	}
	callback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("profile %q: load known hosts %q: %w", c.profile.Name, knownHostsFile, err)
	}
	return callback, nil
}

func authMethods(ctx context.Context, p *config.Profile) ([]ssh.AuthMethod, func(), error) {
	noop := func() {}
	switch p.Auth {
	case "password":
		password := firstEnvironment(profileEnvironment(p.Name, "PASSWORD"), "SSH_MCP_PASSWORD")
		if password == "" {
			return nil, noop, fmt.Errorf("profile %q: set %s or SSH_MCP_PASSWORD", p.Name, profileEnvironment(p.Name, "PASSWORD"))
		}
		return []ssh.AuthMethod{ssh.Password(password)}, noop, nil
	case "key":
		privateKey, err := os.ReadFile(p.KeyRef)
		if err != nil {
			return nil, noop, fmt.Errorf("profile %q: read private key: %w", p.Name, err)
		}
		passphrase := firstEnvironment(profileEnvironment(p.Name, "KEY_PASSPHRASE"), "SSH_MCP_KEY_PASSPHRASE")
		var signer ssh.Signer
		if passphrase == "" {
			signer, err = ssh.ParsePrivateKey(privateKey)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))
		}
		if err != nil {
			return nil, noop, fmt.Errorf("profile %q: parse private key: %w", p.Name, err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, noop, nil
	case "agent":
		agentClient, cleanup, err := connectAgent(ctx)
		if err != nil {
			return nil, noop, fmt.Errorf("profile %q: connect to SSH agent: %w", p.Name, err)
		}
		signers, err := agentClient.Signers()
		if err != nil {
			cleanup()
			return nil, noop, fmt.Errorf("profile %q: list SSH agent keys: %w", p.Name, err)
		}
		if p.AgentKeyFingerprint != "" {
			signers = filterSigners(signers, p.AgentKeyFingerprint)
			if len(signers) == 0 {
				cleanup()
				return nil, noop, fmt.Errorf("profile %q: selected agent key %s is not loaded", p.Name, p.AgentKeyFingerprint)
			}
		}
		if len(signers) == 0 {
			cleanup()
			return nil, noop, fmt.Errorf("profile %q: SSH agent has no keys loaded", p.Name)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, cleanup, nil
	default:
		return nil, noop, fmt.Errorf("profile %q: unsupported auth method %q", p.Name, p.Auth)
	}
}

func filterSigners(signers []ssh.Signer, fingerprint string) []ssh.Signer {
	if fingerprint == "" {
		return signers
	}
	filtered := make([]ssh.Signer, 0, 1)
	for _, signer := range signers {
		if ssh.FingerprintSHA256(signer.PublicKey()) == fingerprint {
			filtered = append(filtered, signer)
		}
	}
	return filtered
}

func agentKeys(ctx context.Context) ([]AgentKeyInfo, error) {
	client, cleanup, err := connectAgent(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	signers, err := client.Signers()
	if err != nil {
		return nil, err
	}
	keys := make([]AgentKeyInfo, 0, len(signers))
	for _, signer := range signers {
		keys = append(keys, AgentKeyInfo{Type: signer.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	}
	return keys, nil
}

func profileEnvironment(profile, suffix string) string {
	var b strings.Builder
	b.WriteString("SSH_MCP_")
	for _, r := range strings.ToUpper(profile) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	b.WriteByte('_')
	b.WriteString(suffix)
	return b.String()
}

func firstEnvironment(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func (c *connection) newSession(ctx context.Context) (*ssh.Session, error) {
	client, err := c.getClient(ctx)
	if err != nil {
		return nil, err
	}
	session, err := c.openSession(ctx, client)
	if err == nil {
		c.changeActive(1)
		return session, nil
	}
	if !isConnectionFailure(err) {
		return nil, fmt.Errorf("open SSH session: %w", err)
	}

	// Opening a channel performs no remote command, so reconnecting and retrying
	// here cannot accidentally execute the caller's command twice.
	c.invalidate(client)
	client, reconnectErr := c.getClient(ctx)
	if reconnectErr != nil {
		return nil, fmt.Errorf("open SSH session (%w), then reconnect: %w", err, reconnectErr)
	}
	session, err = c.openSession(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("open SSH session: %w", err)
	}
	c.changeActive(1)
	return session, nil
}

func (c *connection) openSession(ctx context.Context, client *ssh.Client) (*ssh.Session, error) {
	stop := context.AfterFunc(ctx, func() { c.invalidate(client) })
	session, err := client.NewSession()
	stopped := stop()
	if !stopped && ctx.Err() != nil {
		if session != nil {
			_ = session.Close()
		}
		return nil, ctx.Err()
	}
	return session, err
}

func isConnectionFailure(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "connection is shut down") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "use of closed network connection")
}

func (c *connection) invalidate(client *ssh.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == client {
		_ = c.client.Close()
		c.client = nil
		c.connectedAt = nil
	}
}

func (c *connection) changeActive(delta int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active += delta
	now := time.Now().UTC()
	c.lastActivity = &now
}

func (c *connection) run(ctx context.Context, command string, opts RunOptions) (CommandResult, error) {
	started := time.Now()
	result := CommandResult{Profile: c.profile.Name, ExitCode: -1}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	session, err := c.newSession(ctx)
	if err != nil {
		return result, err
	}
	defer func() {
		_ = session.Close()
		c.changeActive(-1)
	}()

	if opts.TTY || (c.profile.TTY && !opts.DisableTTY) {
		modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if err := session.RequestPty("xterm-256color", 50, 200, modes); err != nil {
			return result, fmt.Errorf("request pseudo-terminal: %w", err)
		}
	}
	if opts.Stdin != "" {
		session.Stdin = strings.NewReader(opts.Stdin)
	}
	capture := newOutputCapture(opts.OutputLimit)
	session.Stdout = capture.writer(false)
	session.Stderr = capture.writer(true)
	if err := session.Start(withWorkdir(c.profile.Workdir, command)); err != nil {
		return result, fmt.Errorf("start remote command: %w", err)
	}

	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	select {
	case err = <-wait:
	case <-ctx.Done():
		signalErr := session.Signal(ssh.SIGKILL)
		_ = session.Close()
		// Wait briefly for the SSH reader to finish so captured output is stable.
		// A buffered wait channel prevents a goroutine leak if a broken server
		// still refuses to close the channel promptly.
		select {
		case <-wait:
		case <-time.After(250 * time.Millisecond):
		}
		result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		result.Error = ctx.Err().Error()
		if signalErr != nil {
			result.Error += "; the remote process may still be running because SSH signal delivery failed: " + signalErr.Error()
		}
		err = ctx.Err()
	}

	result.Stdout, result.Stderr, result.Truncated = capture.values()
	result.DurationMS = time.Since(started).Milliseconds()
	if err == nil {
		result.ExitCode = 0
		return result, nil
	}
	if exitError, ok := errors.AsType[*ssh.ExitError](err); ok {
		result.ExitCode = exitError.ExitStatus()
		result.Signal = exitError.Signal()
		return result, nil
	}
	if result.Error == "" {
		result.Error = err.Error()
	}
	return result, nil
}

func withWorkdir(workdir, command string) string {
	if workdir == "" {
		return command
	}
	return "cd -- " + shellQuote(workdir) + " && " + command
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

type outputCapture struct {
	mu        sync.Mutex
	remaining int
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	truncated bool
}

type captureWriter struct {
	capture *outputCapture
	stderr  bool
}

func newOutputCapture(limit int) *outputCapture {
	if limit <= 0 {
		limit = 1
	}
	return &outputCapture{remaining: limit}
}

func (c *outputCapture) writer(stderr bool) io.Writer {
	return captureWriter{capture: c, stderr: stderr}
}

func (w captureWriter) Write(p []byte) (int, error) {
	w.capture.mu.Lock()
	defer w.capture.mu.Unlock()
	written := len(p)
	n := min(len(p), w.capture.remaining)
	if n < len(p) {
		w.capture.truncated = true
	}
	if n > 0 {
		if w.stderr {
			_, _ = w.capture.stderr.Write(p[:n])
		} else {
			_, _ = w.capture.stdout.Write(p[:n])
		}
		w.capture.remaining -= n
	}
	return written, nil
}

func (c *outputCapture) values() (stdout, stderr string, truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stdout.String(), c.stderr.String(), c.truncated
}

func (c *connection) sftpClient(ctx context.Context) (*sftp.Client, func(), error) {
	client, err := c.getClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	sftpClient, err := c.openSFTPClient(ctx, client)
	if err != nil && isConnectionFailure(err) {
		c.invalidate(client)
		client, err = c.getClient(ctx)
		if err == nil {
			sftpClient, err = c.openSFTPClient(ctx, client)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open SFTP subsystem: %w", err)
	}
	c.changeActive(1)
	stop := context.AfterFunc(ctx, func() { _ = sftpClient.Close() })
	cleanup := func() {
		stop()
		_ = sftpClient.Close()
		c.changeActive(-1)
	}
	return sftpClient, cleanup, nil
}

func (c *connection) openSFTPClient(ctx context.Context, client *ssh.Client) (*sftp.Client, error) {
	stop := context.AfterFunc(ctx, func() { c.invalidate(client) })
	sftpClient, err := sftp.NewClient(client)
	stopped := stop()
	if !stopped && ctx.Err() != nil {
		if sftpClient != nil {
			_ = sftpClient.Close()
		}
		return nil, ctx.Err()
	}
	return sftpClient, err
}

func (c *connection) upload(ctx context.Context, remotePath string, data []byte, mode os.FileMode) (int64, error) {
	if remotePath == "" || strings.IndexByte(remotePath, 0) >= 0 {
		return 0, fmt.Errorf("remotePath must be non-empty and contain no NUL byte")
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return 0, fmt.Errorf("create upload temporary name: %w", err)
	}
	temporary := remotePath + ".ssh-mcp-" + hex.EncodeToString(suffix) + ".tmp"
	keep := false
	defer func() {
		if !keep {
			_ = client.Remove(temporary)
		}
	}()

	file, err := client.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return 0, fmt.Errorf("create remote temporary file: %w", err)
	}
	n, copyErr := io.Copy(file, bytes.NewReader(data))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return n, fmt.Errorf("upload remote file: %w", copyErr)
	}
	if closeErr != nil {
		return n, fmt.Errorf("close remote temporary file: %w", closeErr)
	}
	if syncErr != nil && !sftpOperationUnsupported(syncErr) {
		return n, fmt.Errorf("sync remote temporary file: %w", syncErr)
	}
	if mode == 0 {
		mode = 0o600
	}
	if err := client.Chmod(temporary, mode.Perm()); err != nil {
		return n, fmt.Errorf("set remote file mode: %w", err)
	}
	if err := client.PosixRename(temporary, remotePath); err != nil {
		if _, statErr := client.Lstat(remotePath); statErr == nil {
			return n, fmt.Errorf("atomic replacement is not supported by the remote SFTP server: %w", err)
		} else if !os.IsNotExist(statErr) {
			return n, fmt.Errorf("check remote destination after unsupported posix rename: %w", statErr)
		}
		if renameErr := client.Rename(temporary, remotePath); renameErr != nil {
			return n, fmt.Errorf("create remote file: posix rename: %w; standard rename: %w", err, renameErr)
		}
	}
	keep = true
	return n, nil
}

func sftpOperationUnsupported(err error) bool {
	if errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		return true
	}
	var status *sftp.StatusError
	return errors.As(err, &status) && status.FxCode() == sftp.ErrSSHFxOpUnsupported
}

func (c *connection) download(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	if remotePath == "" || strings.IndexByte(remotePath, 0) >= 0 {
		return nil, fmt.Errorf("remotePath must be non-empty and contain no NUL byte")
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	file, err := client.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("open remote file: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat remote file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("remote path %q is a directory", remotePath)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("remote file is %d bytes; profile transfer limit is %d", info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download remote file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("remote file exceeded profile transfer limit of %d bytes while reading", maxBytes)
	}
	return data, nil
}

func (c *connection) readRange(ctx context.Context, remotePath string, offset, length int64) ([]byte, error) {
	if err := validateRemotePath(remotePath); err != nil {
		return nil, err
	}
	if offset < 0 || length <= 0 {
		return nil, fmt.Errorf("offset must be non-negative and length must be positive")
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	file, err := client.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("open remote file: %w", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek remote file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, length))
	if err != nil {
		return nil, fmt.Errorf("read remote file range: %w", err)
	}
	return data, nil
}

func (c *connection) listDirectory(ctx context.Context, remotePath string, maxEntries int) ([]FileInfo, error) {
	if err := validateRemotePath(remotePath); err != nil {
		return nil, err
	}
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	entries, err := client.ReadDirContext(ctx, remotePath)
	if err != nil {
		return nil, fmt.Errorf("list remote directory: %w", err)
	}
	if len(entries) > maxEntries {
		return nil, fmt.Errorf("remote directory has %d entries; limit is %d", len(entries), maxEntries)
	}
	result := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		result = append(result, portableFileInfo(joinRemote(remotePath, entry.Name()), entry))
	}
	return result, nil
}

func (c *connection) stat(ctx context.Context, remotePath string) (FileInfo, error) {
	if err := validateRemotePath(remotePath); err != nil {
		return FileInfo{}, err
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return FileInfo{}, err
	}
	defer cleanup()
	info, err := client.Lstat(remotePath)
	if err != nil {
		return FileInfo{}, fmt.Errorf("stat remote path: %w", err)
	}
	return portableFileInfo(remotePath, info), nil
}

func (c *connection) checksum(ctx context.Context, remotePath string, maxBytes int64) (string, int64, error) {
	if err := validateRemotePath(remotePath); err != nil {
		return "", 0, err
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return "", 0, err
	}
	defer cleanup()
	file, err := client.Open(remotePath)
	if err != nil {
		return "", 0, fmt.Errorf("open remote file: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat remote file: %w", err)
	}
	if info.Size() > maxBytes {
		return "", 0, fmt.Errorf("remote file is %d bytes; checksum limit is %d", info.Size(), maxBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", n, fmt.Errorf("checksum remote file: %w", err)
	}
	if n > maxBytes {
		return "", n, fmt.Errorf("remote file exceeded checksum limit of %d bytes", maxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func (c *connection) mkdir(ctx context.Context, remotePath string, mode os.FileMode, parents bool) error {
	if err := validateRemotePath(remotePath); err != nil {
		return err
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if parents {
		err = client.MkdirAll(remotePath)
	} else {
		err = client.Mkdir(remotePath)
	}
	if err != nil {
		return fmt.Errorf("create remote directory: %w", err)
	}
	if mode == 0 {
		mode = 0o700
	}
	if err := client.Chmod(remotePath, mode.Perm()); err != nil {
		return fmt.Errorf("set remote directory mode: %w", err)
	}
	return nil
}

func (c *connection) rename(ctx context.Context, oldPath, newPath string, overwrite bool) error {
	if err := validateRemotePath(oldPath); err != nil {
		return fmt.Errorf("oldPath: %w", err)
	}
	if err := validateRemotePath(newPath); err != nil {
		return fmt.Errorf("newPath: %w", err)
	}
	if oldPath == newPath {
		return fmt.Errorf("oldPath and newPath must differ")
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if overwrite {
		if err := client.PosixRename(oldPath, newPath); err != nil {
			return fmt.Errorf("atomically replace remote destination: %w", err)
		}
		return nil
	}
	if _, err := client.Lstat(newPath); err == nil {
		return fmt.Errorf("remote destination %q already exists; set overwrite=true to replace it", newPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check remote destination: %w", err)
	}
	if err := client.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename remote path: %w", err)
	}
	return nil
}

func (c *connection) remove(ctx context.Context, remotePath string) (FileInfo, error) {
	if err := validateRemotePath(remotePath); err != nil {
		return FileInfo{}, err
	}
	client, cleanup, err := c.sftpClient(ctx)
	if err != nil {
		return FileInfo{}, err
	}
	defer cleanup()
	info, err := client.Lstat(remotePath)
	if err != nil {
		return FileInfo{}, fmt.Errorf("stat remote path before removal: %w", err)
	}
	result := portableFileInfo(remotePath, info)
	if info.IsDir() {
		err = client.RemoveDirectory(remotePath)
	} else {
		err = client.Remove(remotePath)
	}
	if err != nil {
		return FileInfo{}, fmt.Errorf("remove remote path (directories must be empty): %w", err)
	}
	return result, nil
}

func validateRemotePath(remotePath string) error {
	if remotePath == "" || strings.IndexByte(remotePath, 0) >= 0 {
		return fmt.Errorf("remotePath must be non-empty and contain no NUL byte")
	}
	return nil
}

func portableFileInfo(remotePath string, info os.FileInfo) FileInfo {
	return FileInfo{
		Name: info.Name(), Path: remotePath, Size: info.Size(), Mode: info.Mode().String(),
		ModeBits: uint32(info.Mode().Perm()), ModTime: info.ModTime().UTC(), IsDir: info.IsDir(),
		IsSymlink: info.Mode()&os.ModeSymlink != 0, IsRegular: info.Mode().IsRegular(),
	}
}

func joinRemote(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return strings.TrimSuffix(dir, "/") + "/" + name
}

func (c *connection) diagnose(ctx context.Context) DiagnosticResult {
	result := DiagnosticResult{
		Profile: c.profile.Name, Address: net.JoinHostPort(c.profile.Host, fmt.Sprint(c.profile.Port)),
		ProxyJump: c.profile.ProxyJump, Auth: c.profile.Auth, SelectedAgentKey: c.profile.AgentKeyFingerprint,
	}
	step := func(name string, started time.Time, err error, okMessage string) {
		item := DiagnosticStep{Name: name, OK: err == nil, DurationMS: time.Since(started).Milliseconds(), Message: okMessage}
		if err != nil {
			item.Message = err.Error()
		}
		result.Steps = append(result.Steps, item)
	}
	started := time.Now()
	addresses, err := net.DefaultResolver.LookupHost(ctx, c.profile.Host)
	step("dns", started, err, strings.Join(addresses, ", "))
	if c.profile.Auth == "agent" {
		started = time.Now()
		keys, keyErr := agentKeys(ctx)
		result.AgentKeys = keys
		step("agent", started, keyErr, fmt.Sprintf("%d key(s) loaded", len(keys)))
	}
	address := net.JoinHostPort(c.profile.Host, fmt.Sprint(c.profile.Port))
	started = time.Now()
	transport, transportErr := c.openTransport(ctx, address)
	if transport != nil {
		_ = transport.Close()
	}
	transportName := "tcp"
	if c.profile.ProxyJump != "" {
		transportName = "proxy-tcp"
	}
	step(transportName, started, transportErr, "remote SSH port is reachable")
	started = time.Now()
	var hostKeyErr error
	client, dialErr := c.dialObserved(ctx, &result.ServerHostKey, &hostKeyErr)
	if client != nil {
		_ = client.Close()
	}
	hostCheckErr := hostKeyErr
	if result.ServerHostKey == "" && hostCheckErr == nil {
		hostCheckErr = fmt.Errorf("SSH handshake did not reach host-key verification")
	}
	step("host-key", started, hostCheckErr, result.ServerHostKey+" verified")
	authErr := dialErr
	if hostKeyErr != nil {
		authErr = fmt.Errorf("authentication was not attempted because host-key verification failed")
	}
	step("authentication", started, authErr, "SSH authentication succeeded")
	result.Success = dialErr == nil
	return result
}

func (c *connection) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return nil
	}
	err := c.client.Close()
	c.client = nil
	c.connectedAt = nil
	return err
}
