package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/config"
	"ssh-mcp/internal/jobs"
	"ssh-mcp/internal/remote"
)

type fakeBackend struct {
	runs     atomic.Int32
	lastRun  string
	lastOpts remote.RunOptions
	uploaded []byte
	download []byte
}

type blockingBackend struct{ *fakeBackend }

func (b *blockingBackend) Run(ctx context.Context, p *config.Profile, command string, opts remote.RunOptions) (remote.CommandResult, error) {
	b.runs.Add(1)
	<-ctx.Done()
	return remote.CommandResult{Profile: p.Name, ExitCode: -1, Error: ctx.Err().Error()}, ctx.Err()
}

func (f *fakeBackend) ListConnections() []remote.ConnectionInfo {
	return []remote.ConnectionInfo{{Profile: "dev", Address: "host:22", User: "deploy", Status: "disconnected"}}
}

func (f *fakeBackend) Run(_ context.Context, p *config.Profile, command string, opts remote.RunOptions) (remote.CommandResult, error) {
	f.lastRun = command
	f.lastOpts = opts
	f.runs.Add(1)
	return remote.CommandResult{Profile: p.Name, Stdout: "ok\n", ExitCode: 0, DurationMS: 2}, nil
}

func (f *fakeBackend) Upload(_ context.Context, _ *config.Profile, _ string, data []byte, _ os.FileMode) (int64, error) {
	f.uploaded = append([]byte(nil), data...)
	return int64(len(data)), nil
}

func (f *fakeBackend) Download(context.Context, *config.Profile, string, int64) ([]byte, error) {
	return append([]byte(nil), f.download...), nil
}

func (f *fakeBackend) ReadRange(_ context.Context, _ *config.Profile, _ string, offset, length int64) ([]byte, error) {
	end := min(int64(len(f.download)), offset+length)
	if offset > end {
		return nil, nil
	}
	return append([]byte(nil), f.download[offset:end]...), nil
}

func (f *fakeBackend) ListDirectory(context.Context, *config.Profile, string, int) ([]remote.FileInfo, error) {
	return []remote.FileInfo{{Name: "file", Path: "/file", Size: int64(len(f.download))}}, nil
}

func (f *fakeBackend) Stat(context.Context, *config.Profile, string) (remote.FileInfo, error) {
	return remote.FileInfo{Name: "file", Path: "/file", Size: int64(len(f.download)), ModeBits: 0o600, IsRegular: true}, nil
}

func (f *fakeBackend) Checksum(context.Context, *config.Profile, string, int64) (string, int64, error) {
	sum := sha256.Sum256(f.download)
	return hex.EncodeToString(sum[:]), int64(len(f.download)), nil
}

func (*fakeBackend) Mkdir(context.Context, *config.Profile, string, os.FileMode, bool) error {
	return nil
}

func (*fakeBackend) Rename(context.Context, *config.Profile, string, string, bool) error {
	return nil
}

func (*fakeBackend) Remove(_ context.Context, _ *config.Profile, path string) (remote.FileInfo, error) {
	return remote.FileInfo{Name: path, Path: path, IsRegular: true}, nil
}

func (f *fakeBackend) Diagnose(context.Context, *config.Profile) remote.DiagnosticResult {
	return remote.DiagnosticResult{Profile: "dev", Success: true, Steps: []remote.DiagnosticStep{{Name: "ssh-handshake", OK: true}}}
}

func (*fakeBackend) Close() error { return nil }

func configuredService(t *testing.T, backend remote.Backend) *Service {
	t.Helper()
	cfg := config.Empty()
	cfg.Defaults.DefaultProfile = "dev"
	cfg.Defaults.ApprovalMode = "never"
	cfg.Profiles = []config.Profile{{Name: "dev", Host: "host", Port: 22, User: "deploy", Auth: "password", AllowUnrestrictedCommands: true}}
	service, err := New(cfg, backend)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func connectClient(t *testing.T, service *Service) *mcp.ClientSession {
	return connectClientOptions(t, service, nil)
}

func connectClientOptions(t *testing.T, service *Service, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := service.MCPServer().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, opts)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession
}

func TestToolSurfaceAndReadCommand(t *testing.T) {
	backend := &fakeBackend{}
	client := connectClient(t, configuredService(t, backend))
	ctx := context.Background()
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{
		"list-connections", "read-command", "run-command", "start-command", "job-status", "cancel-job",
		"run-command-template", "diagnose-connection", "sftp-upload", "sftp-download", "sftp-list",
		"sftp-stat", "sftp-read", "sftp-checksum", "sftp-write", "sftp-apply-patch", "audit-list", "audit-verify",
		"sftp-mkdir", "sftp-rename", "sftp-remove",
	} {
		if !slices.Contains(names, want) {
			t.Errorf("tools %v do not contain %q", names, want)
		}
	}

	result, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "read-command", Arguments: map[string]any{"command": "ls -la"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || backend.runs.Load() != 1 || backend.lastRun != "ls -la" {
		t.Fatalf("result=%+v runs=%d command=%q", result, backend.runs.Load(), backend.lastRun)
	}
	if backend.lastOpts.Timeout != 60*time.Second || backend.lastOpts.OutputLimit != 1_048_576 {
		t.Fatalf("unexpected run options: %+v", backend.lastOpts)
	}
}

func TestRiskyCommandUsesElicitation(t *testing.T) {
	backend := &fakeBackend{}
	service := configuredService(t, backend)
	service.cfg.Defaults.ApprovalMode = "risky"
	client := connectClientOptions(t, service, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": true}}, nil
		},
	})
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "run-command", Arguments: map[string]any{"command": "sudo systemctl restart demo"},
	})
	if err != nil || result.IsError || backend.runs.Load() != 1 {
		t.Fatalf("result=%+v err=%v runs=%d", result, err, backend.runs.Load())
	}
}

func TestTasksExtensionCreationAndGet(t *testing.T) {
	backend := &fakeBackend{}
	service := configuredService(t, backend)
	var created *taskResult
	service.MCPServer().AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, request)
			if task, ok := result.(*taskResult); ok && task.ResultType == "task" {
				created = task
			}
			return result, err
		}
	})
	capabilities := &mcp.ClientCapabilities{}
	capabilities.AddExtension(tasksExtension, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := service.MCPServer().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverSession.Close() }()
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "task-test", Version: "1"}, &mcp.ClientOptions{Capabilities: capabilities})
	if err := mcp.AddSendingCustomMethod[*taskParams, *taskResult](mcpClient, "tasks/get"); err != nil {
		t.Fatal(err)
	}
	client, err := mcpClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	_, err = client.CallTool(ctx, &mcp.CallToolParams{
		Name: "start-command", Arguments: map[string]any{"command": "go test ./..."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created == nil || created.TaskID == "" || created.Status != jobs.Working {
		t.Fatalf("created task = %+v", created)
	}
	deadline := time.Now().Add(time.Second)
	var got *taskResult
	for time.Now().Before(deadline) {
		got, err = mcp.CallCustomMethod[*taskParams, *taskResult](ctx, client, "tasks/get", &taskParams{TaskID: created.TaskID})
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == jobs.Completed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got == nil || got.Status != jobs.Completed || got.ResultType != "complete" || got.Result == nil {
		t.Fatalf("completed task = %+v", got)
	}
}

func TestTaskMethodsRequireNegotiatedCapability(t *testing.T) {
	service := configuredService(t, &fakeBackend{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := service.MCPServer().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverSession.Close() }()
	client := mcp.NewClient(&mcp.Implementation{Name: "no-tasks", Version: "1"}, nil)
	if err := mcp.AddSendingCustomMethod[*taskParams, *taskResult](client, "tasks/get"); err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	_, err = mcp.CallCustomMethod[*taskParams, *taskResult](ctx, session, "tasks/get", &taskParams{TaskID: "not-a-task"})
	var rpcError *jsonrpc.Error
	if !errors.As(err, &rpcError) || rpcError.Code != mcp.CodeMissingRequiredClientCapabilities {
		t.Fatalf("error = %v, want missing capability code", err)
	}
}

func TestApprovalStateIsBoundAndOneTime(t *testing.T) {
	service := configuredService(t, &fakeBackend{})
	state, err := service.signApprovalState("command", "dev", "sudo true")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.verifyApprovalState(state, "command", "dev", "sudo true"); err != nil {
		t.Fatal(err)
	}
	if err := service.verifyApprovalState(state, "command", "dev", "sudo true"); err == nil {
		t.Fatal("approval response state was replayable")
	}
	modified, err := service.signApprovalState("command", "dev", "sudo true")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.verifyApprovalState(modified, "command", "dev", "sudo false"); err == nil {
		t.Fatal("approval response was accepted for a modified command")
	}
}

func TestApprovalStateHandlesStructuralCharacters(t *testing.T) {
	service := configuredService(t, &fakeBackend{})
	state, err := service.signApprovalState("command", "dev\nprofile", "line one\nline two")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.verifyApprovalState(state, "command", "dev\nprofile", "line one\nline two"); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalBindingCoversFileContentAndCommandOptions(t *testing.T) {
	service := configuredService(t, &fakeBackend{})
	uploadA := uploadApprovalBinding("/tmp/file", []byte("a"), 0o600)
	uploadB := uploadApprovalBinding("/tmp/file", []byte("b"), 0o600)
	state, err := service.signApprovalState("file-write", "dev", uploadA)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.verifyApprovalState(state, "file-write", "dev", uploadB); err == nil {
		t.Fatal("approval accepted modified upload content")
	}
	commandA := commandApprovalBinding("deploy", false, "yes\n")
	commandB := commandApprovalBinding("deploy", true, "yes\n")
	state, err = service.signApprovalState("command", "dev", commandA)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.verifyApprovalState(state, "command", "dev", commandB); err == nil {
		t.Fatal("approval accepted modified command options")
	}
	patchA := patchApprovalBinding("x", "y\nexpected-sha256=z", "patch")
	patchB := patchApprovalBinding("x\nexpected-sha256=y", "z", "patch")
	if patchA == patchB {
		t.Fatal("approval binding is ambiguous when paths contain structural characters")
	}
}

func TestArbitraryCommandsRequireAllowlistOrExplicitOptIn(t *testing.T) {
	backend := &fakeBackend{}
	service := configuredService(t, backend)
	service.cfg.Profiles[0].AllowUnrestrictedCommands = false
	client := connectClient(t, service)
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "run-command", Arguments: map[string]any{"command": "echo hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || backend.runs.Load() != 0 {
		t.Fatalf("result=%+v runs=%d", result, backend.runs.Load())
	}
}

func TestBackgroundProgressAndCancellation(t *testing.T) {
	backend := &blockingBackend{fakeBackend: &fakeBackend{}}
	service := configuredService(t, backend)
	var notifications atomic.Int32
	client := connectClientOptions(t, service, &mcp.ClientOptions{
		ProgressNotificationHandler: func(context.Context, *mcp.ProgressNotificationClientRequest) {
			notifications.Add(1)
		},
	})
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "start-command", Meta: mcp.Meta{"progressToken": "job-progress"},
		Arguments: map[string]any{"command": "long-running"},
	})
	if err != nil || result.IsError {
		t.Fatalf("start-command = %+v, %v", result, err)
	}
	listed := service.jobs.List()
	if len(listed) != 1 {
		t.Fatalf("jobs = %+v", listed)
	}
	if _, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "cancel-job", Arguments: map[string]any{"jobId": listed[0].ID},
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err := service.jobs.Get(listed[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == jobs.Cancelled && notifications.Load() >= 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job was not cancelled with progress; jobs=%+v notifications=%d", service.jobs.List(), notifications.Load())
}

func TestBackgroundFallbackAndPatch(t *testing.T) {
	backend := &fakeBackend{download: []byte("one\ntwo\n")}
	client := connectClient(t, configuredService(t, backend))
	started, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "start-command", Arguments: map[string]any{"command": "go test ./..."},
	})
	if err != nil || started.IsError {
		t.Fatalf("start-command result=%+v err=%v", started, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && backend.runs.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	if backend.runs.Load() != 1 {
		t.Fatal("background command did not run")
	}
	sum := sha256.Sum256(backend.download)
	patched, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "sftp-apply-patch", Arguments: map[string]any{
			"remotePath": "/file", "expectedSha256": hex.EncodeToString(sum[:]),
			"patch": "@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n",
		},
	})
	if err != nil || patched.IsError || string(backend.uploaded) != "one\nTWO\n" {
		t.Fatalf("patch result=%+v err=%v uploaded=%q", patched, err, backend.uploaded)
	}
}

func TestPolicyDenialDoesNotReachBackend(t *testing.T) {
	backend := &fakeBackend{}
	client := connectClient(t, configuredService(t, backend))
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "run-command", Arguments: map[string]any{"command": "rm -rf /"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || backend.runs.Load() != 0 {
		t.Fatalf("result=%+v backend runs=%d, want tool error and no run", result, backend.runs.Load())
	}
}

func TestSFTPEncoding(t *testing.T) {
	backend := &fakeBackend{download: []byte{0, 1, 2}}
	client := connectClient(t, configuredService(t, backend))
	ctx := context.Background()
	upload, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "sftp-upload", Arguments: map[string]any{
			"remotePath": "/tmp/data", "content": "aGVsbG8=", "encoding": "base64",
		},
	})
	if err != nil || upload.IsError {
		t.Fatalf("upload result=%+v err=%v", upload, err)
	}
	if string(backend.uploaded) != "hello" {
		t.Fatalf("uploaded = %q", backend.uploaded)
	}
	download, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "sftp-download", Arguments: map[string]any{"remotePath": "/tmp/data", "encoding": "base64"},
	})
	if err != nil || download.IsError {
		t.Fatalf("download result=%+v err=%v", download, err)
	}
}
