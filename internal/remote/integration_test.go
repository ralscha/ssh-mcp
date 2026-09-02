package remote

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"ssh-mcp/internal/config"
)

type testSSHServer struct {
	listener    net.Listener
	fingerprint string
	root        string
}

func startTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if metadata.User() != "deploy" || string(password) != "secret" {
				return nil, fmt.Errorf("invalid credentials")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testSSHServer{
		listener: listener, fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), root: t.TempDir(),
	}
	go server.serve(serverConfig)
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (s *testSSHServer) serve(serverConfig *ssh.ServerConfig) {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			conn, channels, requests, err := ssh.NewServerConn(raw, serverConfig)
			if err != nil {
				_ = raw.Close()
				return
			}
			defer func() { _ = conn.Close() }()
			go ssh.DiscardRequests(requests)
			for newChannel := range channels {
				if newChannel.ChannelType() == "direct-tcpip" {
					go handleTestForward(newChannel)
					continue
				}
				if newChannel.ChannelType() != "session" {
					_ = newChannel.Reject(ssh.UnknownChannelType, "session channels only")
					continue
				}
				channel, channelRequests, err := newChannel.Accept()
				if err != nil {
					continue
				}
				go s.handleSession(channel, channelRequests)
			}
		}()
	}
}

func handleTestForward(newChannel ssh.NewChannel) {
	var request struct {
		Host           string
		Port           uint32
		OriginatorHost string
		OriginatorPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &request); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, "invalid forwarding request")
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(request.Host, fmt.Sprint(request.Port)))
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = upstream.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	go func() {
		_, _ = io.Copy(channel, upstream)
		_ = channel.CloseWrite()
	}()
	_, _ = io.Copy(upstream, channel)
	_ = upstream.Close()
	_ = channel.Close()
}

func (s *testSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	for request := range requests {
		switch request.Type {
		case "pty-req", "env":
			_ = request.Reply(true, nil)
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
				_ = request.Reply(false, nil)
				_ = channel.Close()
				return
			}
			_ = request.Reply(true, nil)
			_, _ = io.WriteString(channel, "executed: "+payload.Command+"\n")
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			_ = channel.Close()
			return
		case "subsystem":
			var payload struct{ Name string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
				_ = request.Reply(false, nil)
				continue
			}
			_ = request.Reply(true, nil)
			server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(s.root))
			if err == nil {
				_ = server.Serve()
				_ = server.Close()
			}
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
	_ = channel.Close()
}

func (s *testSSHServer) profile(t *testing.T) (*config.Config, *config.Profile) {
	t.Helper()
	host, portText, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatal(err)
	}
	cfg := config.Empty()
	cfg.Defaults.DefaultProfile = "test"
	cfg.Profiles = []config.Profile{{
		Name: "test", Host: host, Port: port, User: "deploy", Auth: "password", TrustedHostKey: s.fingerprint,
	}}
	return cfg, &cfg.Profiles[0]
}

func TestManagerExecAndSFTPAgainstRealSSHServer(t *testing.T) {
	server := startTestSSHServer(t)
	cfg, profile := server.profile(t)
	t.Setenv("SSH_MCP_TEST_PASSWORD", "secret")
	manager := NewManager(cfg)
	t.Cleanup(func() { _ = manager.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := manager.Run(ctx, profile, "printf hello", RunOptions{Timeout: time.Second, OutputLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.Stdout != "executed: printf hello\n" {
		t.Fatalf("Run result = %+v", result)
	}

	payload := []byte{0, 1, 2, 3, 4}
	n, err := manager.Upload(ctx, profile, "data.bin", payload, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("Upload bytes = %d, want %d", n, len(payload))
	}
	local, err := os.ReadFile(filepath.Join(server.root, "data.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(local) != string(payload) {
		t.Fatalf("uploaded content = %v, want %v", local, payload)
	}
	downloaded, err := manager.Download(ctx, profile, "data.bin", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(downloaded) != string(payload) {
		t.Fatalf("downloaded content = %v, want %v", downloaded, payload)
	}
	partial, err := manager.ReadRange(ctx, profile, "data.bin", 1, 2)
	if err != nil || string(partial) != string(payload[1:3]) {
		t.Fatalf("ReadRange = %v, %v", partial, err)
	}
	stat, err := manager.Stat(ctx, profile, "data.bin")
	if err != nil || stat.Size != int64(len(payload)) || stat.IsDir {
		t.Fatalf("Stat = %+v, %v", stat, err)
	}
	entries, err := manager.ListDirectory(ctx, profile, ".", 10)
	if err != nil || len(entries) != 1 || entries[0].Name != "data.bin" {
		t.Fatalf("ListDirectory = %+v, %v", entries, err)
	}
	checksum, n, err := manager.Checksum(ctx, profile, "data.bin", 1024)
	wantSum := sha256.Sum256(payload)
	if err != nil || checksum != fmt.Sprintf("%x", wantSum) || n != int64(len(payload)) {
		t.Fatalf("Checksum = %s, %d, %v", checksum, n, err)
	}
	diagnostics := manager.Diagnose(ctx, profile)
	if !diagnostics.Success || diagnostics.ServerHostKey != server.fingerprint {
		t.Fatalf("Diagnose = %+v", diagnostics)
	}
	if err := manager.Mkdir(ctx, profile, "nested/leaf", 0o750, true); err != nil {
		t.Fatalf("Mkdir = %v", err)
	}
	if _, err := manager.Upload(ctx, profile, "nested/leaf/old.txt", []byte("move me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rename(ctx, profile, "nested/leaf/old.txt", "nested/leaf/new.txt", false); err != nil {
		t.Fatalf("Rename = %v", err)
	}
	removed, err := manager.Remove(ctx, profile, "nested/leaf/new.txt")
	if err != nil || !removed.IsRegular {
		t.Fatalf("Remove file = %+v, %v", removed, err)
	}
	if _, err := manager.Remove(ctx, profile, "nested/leaf"); err != nil {
		t.Fatalf("Remove directory = %v", err)
	}
	if _, err := manager.Remove(ctx, profile, "nested"); err != nil {
		t.Fatalf("Remove parent directory = %v", err)
	}

	infos := manager.ListConnections()
	if len(infos) != 1 || infos[0].Status != "connected" || infos[0].Active != 0 {
		t.Fatalf("connection info = %+v", infos)
	}
}

func TestManagerProxyJump(t *testing.T) {
	jumpServer := startTestSSHServer(t)
	targetServer := startTestSSHServer(t)
	jumpCfg, jumpProfile := jumpServer.profile(t)
	_, targetProfile := targetServer.profile(t)
	jumpProfile.Name = "jump"
	targetProfile.Name = "target"
	targetProfile.ProxyJump = "jump"
	jumpCfg.Defaults.DefaultProfile = "target"
	jumpCfg.Profiles = []config.Profile{*jumpProfile, *targetProfile}
	t.Setenv("SSH_MCP_PASSWORD", "secret")
	manager := NewManager(jumpCfg)
	t.Cleanup(func() { _ = manager.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := manager.Run(ctx, &jumpCfg.Profiles[1], "hostname", RunOptions{Timeout: time.Second, OutputLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.Stdout != "executed: hostname\n" {
		t.Fatalf("proxy jump result = %+v", result)
	}
}

func TestManagerRejectsWrongHostKey(t *testing.T) {
	server := startTestSSHServer(t)
	cfg, profile := server.profile(t)
	profile.TrustedHostKey = "SHA256:not-the-server-key"
	t.Setenv("SSH_MCP_TEST_PASSWORD", "secret")
	manager := NewManager(cfg)
	t.Cleanup(func() { _ = manager.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := manager.Run(ctx, profile, "true", RunOptions{Timeout: time.Second, OutputLimit: 1024})
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("Run error = %v, want host key mismatch", err)
	}
}
