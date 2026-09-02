package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStdioTransportListsTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	configPath := writeSmokeConfig(t, "")
	cmd := exec.CommandContext(ctx, "go", "run", ".", "--config", configPath) //nolint:gosec // fixed test executable with a temporary config path
	client := mcp.NewClient(&mcp.Implementation{Name: "smoke-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect over stdio: %v", err)
	}
	defer func() { _ = session.Close() }()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if !containsTool(result.Tools, "read-command") || !containsTool(result.Tools, "sftp-remove") {
		t.Fatalf("expected production tool surface, got %d tools", len(result.Tools))
	}
}

func TestHTTPTransportListsToolsWithBearerAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	address := "127.0.0.1:" + strconv.Itoa(port)
	configPath := writeSmokeConfig(t, fmt.Sprintf("[http]\nenabled = true\nlisten = %q\npath = \"/mcp\"\nauthMode = \"token\"\ntokenEnv = \"TEST_SSH_MCP_E2E_TOKEN\"\n", address))
	executable := filepath.Join(t.TempDir(), "ssh-mcp.exe")
	build := exec.CommandContext(ctx, "go", "build", "-o", executable, ".") //nolint:gosec // fixed Go tool invocation in an integration test
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, output)
	}
	cmd := exec.CommandContext(ctx, executable, "--config", configPath) //nolint:gosec // executes the binary built by this test
	cmd.Env = append(os.Environ(), "TEST_SSH_MCP_E2E_TOKEN=correct-secret")
	var logs lockedBuffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exit := make(chan error, 1)
	go func() { exit <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			<-exit
		}
	}()

	httpClient := &http.Client{Transport: bearerRoundTripper{token: "correct-secret", next: http.DefaultTransport}}
	client := mcp.NewClient(&mcp.Implementation{Name: "http-smoke-test", Version: "1.0.0"}, nil)
	deadline := time.Now().Add(20 * time.Second)
	var session *mcp.ClientSession
	for {
		select {
		case err := <-exit:
			t.Fatalf("server exited early: %v\n%s", err, logs.String())
		default:
		}
		session, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp", HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect over HTTP: %v\n%s", err, logs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer func() { _ = session.Close() }()
	result, err := session.ListTools(ctx, nil)
	if err != nil || !containsTool(result.Tools, "list-connections") {
		t.Fatalf("HTTP tools/list: tools=%v err=%v", result, err)
	}
}

func TestVersionOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", ".", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "ssh-mcp 1.0.0" {
		t.Fatalf("version = %q", got)
	}
}

func writeSmokeConfig(t *testing.T, httpConfig string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	content := httpConfig + `
[[profiles]]
name = "dev"
host = "example.test"
user = "deploy"
auth = "password"
allowedCommands = ["^true$"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func containsTool(tools []*mcp.Tool, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

type bearerRoundTripper struct {
	token string
	next  http.RoundTripper
}

func (r bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request.Header.Set("Authorization", "Bearer "+r.token)
	return r.next.RoundTrip(request)
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
