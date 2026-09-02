package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/audit"
	"ssh-mcp/internal/config"
	"ssh-mcp/internal/jobs"
	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/remote"
)

// Version may be overridden by release builds with -ldflags. The source
// fallback identifies untagged 1.0 builds and keeps --version deterministic.
var Version = "1.0.0"

func ServerVersion() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// Service owns the MCP-facing application rules. Network operations remain in
// Backend, so no tool handler can accidentally bypass profile resolution or
// policy checks.
type Service struct {
	cfg           *config.Config
	policy        *policy.Engine
	backend       remote.Backend
	audit         *audit.Writer
	jobs          *jobs.Manager
	mcp           *mcp.Server
	approvalKey   []byte
	approvalMu    sync.Mutex
	usedApprovals map[string]time.Time
}

func New(cfg *config.Config, backend remote.Backend) (*Service, error) {
	engine, err := policy.New(cfg)
	if err != nil {
		return nil, err
	}
	auditor, err := audit.New(cfg.Defaults.AuditLog, cfg.Defaults.AuditRedact)
	if err != nil {
		return nil, err
	}
	jobManager, err := jobs.New(cfg.Defaults.JobStateFile, time.Duration(cfg.Defaults.JobRetentionMS)*time.Millisecond, cfg.Defaults.MaxJobs)
	if err != nil {
		return nil, err
	}
	approvalKey := make([]byte, 32)
	if _, err := rand.Read(approvalKey); err != nil {
		return nil, fmt.Errorf("initialize approval state signing key: %w", err)
	}
	s := &Service{cfg: cfg, policy: engine, backend: backend, audit: auditor, jobs: jobManager, approvalKey: approvalKey, usedApprovals: make(map[string]time.Time)}
	s.mcp = s.buildMCPServer()
	return s, nil
}

// MCPServer returns a fully registered MCP server. The caller chooses the
// transport, which keeps stdio wiring out of the reusable application layer.
func (s *Service) MCPServer() *mcp.Server {
	return s.mcp
}

func (s *Service) buildMCPServer() *mcp.Server {
	capabilities := &mcp.ServerCapabilities{}
	capabilities.AddExtension(tasksExtension, nil)
	server := mcp.NewServer(
		&mcp.Implementation{Name: "ssh-mcp", Version: ServerVersion()},
		&mcp.ServerOptions{
			Instructions: "Use list-connections first. Prefer structured SFTP and command-template tools; use arbitrary run-command only when necessary. Risky operations may require human approval.",
			Capabilities: capabilities,
		},
	)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list-connections",
		Description: "List configured SSH profiles and their current connection status without opening a connection.",
		Annotations: annotations(true, false),
	}, s.listConnections)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "read-command",
		Description: "Run one allowlisted read-only command on a configured SSH profile. Shell operators and redirections are rejected.",
		Annotations: annotations(true, false),
	}, s.readCommand)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "run-command",
		Description: "Run a shell command on a configured SSH profile after applying deny/allow rules and built-in catastrophic-command protection.",
		Annotations: annotations(false, true),
	}, s.runCommand)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "sftp-upload",
		Description: "Upload UTF-8 or base64 content to a remote path using SFTP and an atomic temporary-file rename.",
		Annotations: annotations(false, true),
	}, s.upload)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "sftp-download",
		Description: "Download a size-limited remote file over SFTP as UTF-8 or base64 content.",
		Annotations: annotations(true, false),
	}, s.download)
	s.registerCommandTools(server)
	s.registerFileTools(server)
	s.registerAuditTools(server)
	s.registerTaskMethods(server)
	return server
}

func annotations(readOnly, destructive bool) *mcp.ToolAnnotations {
	openWorld := true
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    readOnly,
		DestructiveHint: new(destructive),
		OpenWorldHint:   &openWorld,
	}
}

type listConnectionsInput struct{}

type listConnectionsOutput struct {
	Connections []remote.ConnectionInfo `json:"connections"`
}

func (s *Service) listConnections(context.Context, *mcp.CallToolRequest, listConnectionsInput) (*mcp.CallToolResult, listConnectionsOutput, error) {
	if len(s.cfg.Profiles) == 0 {
		return nil, listConnectionsOutput{}, fmt.Errorf("ssh-mcp is not configured; create the config file and add at least one [[profiles]] entry")
	}
	return nil, listConnectionsOutput{Connections: s.backend.ListConnections()}, nil
}

type commandInput struct {
	Command string `json:"command" jsonschema:"shell command to execute"`
	Profile string `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
	TTY     bool   `json:"tty,omitempty" jsonschema:"allocate a pseudo-terminal"`
	Stdin   string `json:"stdin,omitempty" jsonschema:"optional standard input sent to the command"`
}

type readCommandInput struct {
	Command string `json:"command" jsonschema:"read-only shell command to execute"`
	Profile string `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
}

func (s *Service) readCommand(ctx context.Context, _ *mcp.CallToolRequest, input readCommandInput) (*mcp.CallToolResult, remote.CommandResult, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	if err := s.policy.AuthorizeCommand(s.cfg, profile, input.Command, true); err != nil {
		_ = s.record(audit.Event{Action: "read-command", Profile: profile.Name, Command: input.Command, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return nil, remote.CommandResult{}, fmt.Errorf("policy denied read-command: %w", err)
	}
	return s.execute(ctx, profile, commandInput{Command: input.Command, Profile: input.Profile}, "read-command", "allowed")
}

func (s *Service) runCommand(ctx context.Context, req *mcp.CallToolRequest, input commandInput) (*mcp.CallToolResult, remote.CommandResult, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	if err := allowArbitraryCommand(profile); err != nil {
		_ = s.record(audit.Event{Action: "run-command", Profile: profile.Name, Command: input.Command, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return nil, remote.CommandResult{}, err
	}
	if err := s.policy.AuthorizeCommand(s.cfg, profile, input.Command, false); err != nil {
		_ = s.record(audit.Event{Action: "run-command", Profile: profile.Name, Command: input.Command, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return nil, remote.CommandResult{}, fmt.Errorf("policy denied run-command: %w", err)
	}
	command := strings.TrimSpace(input.Command)
	decision, pending, err := s.requireApproval(ctx, req, profile, "command", command, commandApprovalBinding(command, input.TTY, input.Stdin), false)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	if pending != nil {
		return pending, remote.CommandResult{}, nil
	}
	return s.execute(ctx, profile, input, "run-command", decision)
}

func (s *Service) execute(ctx context.Context, profile *config.Profile, input commandInput, action, decision string) (*mcp.CallToolResult, remote.CommandResult, error) {
	if int64(len(input.Stdin)) > s.cfg.TransferLimit(profile) {
		return nil, remote.CommandResult{}, fmt.Errorf("stdin is %d bytes; profile transfer limit is %d", len(input.Stdin), s.cfg.TransferLimit(profile))
	}
	started := time.Now()
	result, err := s.backend.Run(ctx, profile, strings.TrimSpace(input.Command), remote.RunOptions{
		TTY:         input.TTY,
		DisableTTY:  action == "read-command",
		Stdin:       input.Stdin,
		Timeout:     time.Duration(s.cfg.CommandTimeout(profile)) * time.Millisecond,
		OutputLimit: s.cfg.OutputLimit(profile),
	})
	if err != nil {
		_ = s.record(audit.Event{Action: action, Profile: profile.Name, Command: input.Command, Decision: decision, Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, remote.CommandResult{}, err
	}
	exit := result.ExitCode
	if auditErr := s.record(audit.Event{Action: action, Profile: profile.Name, Command: input.Command, Decision: decision, Outcome: commandOutcome(result), DurationMS: result.DurationMS, ExitCode: &exit, Error: result.Error}); auditErr != nil {
		return nil, remote.CommandResult{}, fmt.Errorf("command completed but audit logging failed: %w", auditErr)
	}
	toolResult := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: formatCommandResult(result)}},
		IsError: result.ExitCode != 0 || result.Error != "",
	}
	return toolResult, result, nil
}

func formatCommandResult(result remote.CommandResult) string {
	var b strings.Builder
	if result.Stdout != "" {
		b.WriteString(result.Stdout)
		if !strings.HasSuffix(result.Stdout, "\n") {
			b.WriteByte('\n')
		}
	}
	if result.Stderr != "" {
		b.WriteString("[stderr]\n")
		b.WriteString(result.Stderr)
		if !strings.HasSuffix(result.Stderr, "\n") {
			b.WriteByte('\n')
		}
	}
	fmt.Fprintf(&b, "[exit=%d duration=%dms", result.ExitCode, result.DurationMS)
	if result.Signal != "" {
		fmt.Fprintf(&b, " signal=%s", result.Signal)
	}
	if result.Truncated {
		b.WriteString(" output-truncated")
	}
	if result.TimedOut {
		b.WriteString(" timed-out")
	}
	b.WriteString("]")
	if result.Error != "" {
		b.WriteString("\n")
		b.WriteString(result.Error)
	}
	return b.String()
}

type uploadInput struct {
	RemotePath string `json:"remotePath" jsonschema:"absolute or home-relative path on the remote host"`
	Content    string `json:"content" jsonschema:"UTF-8 text or base64-encoded bytes"`
	Encoding   string `json:"encoding,omitempty" jsonschema:"content encoding: utf8 (default) or base64"`
	Mode       int    `json:"mode,omitempty" jsonschema:"optional Unix permission bits as a decimal integer; defaults to 0600"`
	Profile    string `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
}

type uploadOutput struct {
	Profile    string `json:"profile"`
	RemotePath string `json:"remotePath"`
	Bytes      int64  `json:"bytes"`
}

func (s *Service) upload(ctx context.Context, req *mcp.CallToolRequest, input uploadInput) (*mcp.CallToolResult, uploadOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, uploadOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, uploadOutput{}, err
	}
	action := "sftp-upload"
	if req != nil && req.Params.Name != "" {
		action = req.Params.Name
	}
	if err := s.policy.AuthorizeWrite(profile); err != nil {
		_ = s.record(audit.Event{Action: action, Profile: profile.Name, Target: input.RemotePath, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return nil, uploadOutput{}, fmt.Errorf("policy denied %s: %w", action, err)
	}
	data, err := decodeContent(input.Content, input.Encoding)
	if err != nil {
		return nil, uploadOutput{}, err
	}
	limit := s.cfg.TransferLimit(profile)
	if int64(len(data)) > limit {
		return nil, uploadOutput{}, fmt.Errorf("upload is %d bytes; profile transfer limit is %d", len(data), limit)
	}
	if input.Mode < 0 || input.Mode > 0o777 {
		return nil, uploadOutput{}, fmt.Errorf("mode must be between 0 and 0777")
	}
	mode := os.FileMode(input.Mode)
	if mode == 0 {
		mode = 0o600
	}
	decision, pending, err := s.requireApproval(ctx, req, profile, "file-write", input.RemotePath, uploadApprovalBinding(input.RemotePath, data, mode), false)
	if err != nil {
		return nil, uploadOutput{}, err
	}
	if pending != nil {
		return pending, uploadOutput{}, nil
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	n, err := s.backend.Upload(ctx, profile, input.RemotePath, data, mode)
	if err != nil {
		_ = s.record(audit.Event{Action: action, Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Bytes: n, Error: err.Error()})
		return nil, uploadOutput{}, err
	}
	if err := s.record(audit.Event{Action: action, Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "completed", DurationMS: time.Since(started).Milliseconds(), Bytes: n}); err != nil {
		return nil, uploadOutput{}, fmt.Errorf("upload completed but audit logging failed: %w", err)
	}
	output := uploadOutput{Profile: profile.Name, RemotePath: input.RemotePath, Bytes: n}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Uploaded %d bytes to %s on %s", n, input.RemotePath, profile.Name)}}}, output, nil
}

func decodeContent(content, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "", "utf8", "utf-8", "text":
		return []byte(content), nil
	case "base64":
		data, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return nil, fmt.Errorf("decode base64 content: %w", err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("encoding must be utf8 or base64")
	}
}

type downloadInput struct {
	RemotePath string `json:"remotePath" jsonschema:"path on the remote host"`
	Encoding   string `json:"encoding,omitempty" jsonschema:"response encoding: utf8 (default) or base64"`
	Profile    string `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
}

type downloadOutput struct {
	Profile    string `json:"profile"`
	RemotePath string `json:"remotePath"`
	Encoding   string `json:"encoding"`
	Content    string `json:"content"`
	Bytes      int64  `json:"bytes"`
}

func (s *Service) download(ctx context.Context, _ *mcp.CallToolRequest, input downloadInput) (*mcp.CallToolResult, downloadOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, downloadOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, downloadOutput{}, err
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	data, err := s.backend.Download(ctx, profile, input.RemotePath, s.cfg.TransferLimit(profile))
	if err != nil {
		_ = s.record(audit.Event{Action: "sftp-download", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, downloadOutput{}, err
	}
	encoding := strings.ToLower(input.Encoding)
	var content string
	switch encoding {
	case "", "utf8", "utf-8", "text":
		if !utf8.Valid(data) {
			return nil, downloadOutput{}, fmt.Errorf("remote file is not valid UTF-8; retry with encoding=base64")
		}
		encoding = "utf8"
		content = string(data)
	case "base64":
		content = base64.StdEncoding.EncodeToString(data)
	default:
		return nil, downloadOutput{}, fmt.Errorf("encoding must be utf8 or base64")
	}
	output := downloadOutput{
		Profile: profile.Name, RemotePath: input.RemotePath, Encoding: encoding,
		Content: content, Bytes: int64(len(data)),
	}
	if err := s.record(audit.Event{Action: "sftp-download", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "completed", DurationMS: time.Since(started).Milliseconds(), Bytes: int64(len(data))}); err != nil {
		return nil, downloadOutput{}, fmt.Errorf("download completed but audit logging failed: %w", err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: content}}}, output, nil
}

func commandOutcome(result remote.CommandResult) string {
	if result.Error != "" || result.ExitCode != 0 {
		return "failed"
	}
	return "completed"
}

func allowArbitraryCommand(profile *config.Profile) error {
	if len(profile.AllowedCommands) == 0 && !profile.AllowUnrestrictedCommands {
		return fmt.Errorf("profile %q does not enable arbitrary commands; configure allowedCommands, set allowUnrestrictedCommands=true, or use a command template", profile.Name)
	}
	return nil
}

func (s *Service) transferContext(ctx context.Context, profile *config.Profile) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(s.cfg.TransferTimeout(profile))*time.Millisecond)
}
