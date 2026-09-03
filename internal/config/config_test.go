package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestLoadDefaultsAndSingleProfile(t *testing.T) {
	path := writeConfig(t, `
[[profiles]]
name = "dev"
host = "example.test"
user = "deploy"
auth = "password"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.DefaultProfile != "dev" {
		t.Fatalf("default profile = %q, want dev", cfg.Defaults.DefaultProfile)
	}
	p, err := cfg.Profile("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 22 || cfg.CommandTimeout(p) != 60_000 || cfg.OutputLimit(p) != 1_048_576 {
		t.Fatalf("unexpected defaults: profile=%+v defaults=%+v", p, cfg.Defaults)
	}
}

func TestLoadRejectsUnknownAndSecretFields(t *testing.T) {
	path := writeConfig(t, `
[[profiles]]
name = "dev"
host = "example.test"
user = "deploy"
auth = "password"
password = "must-not-be-accepted"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "profiles.password") {
		t.Fatalf("Load error = %v, want unknown profiles.password", err)
	}
}

func TestLoadRejectsInvalidProfile(t *testing.T) {
	path := writeConfig(t, `
[[profiles]]
name = "dev"
host = "example.test"
user = "deploy"
auth = "key"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "keyRef is required") {
		t.Fatalf("Load error = %v, want missing keyRef", err)
	}
}

func TestEmptyIsIntrospectableButNotUsable(t *testing.T) {
	cfg := Empty()
	if _, err := cfg.Profile(""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Profile error = %v, want not configured", err)
	}
}

func TestHTTPPathRejectsServeMuxWildcards(t *testing.T) {
	cfg := Empty()
	cfg.HTTP.Path = "/mcp/{tenant}"
	if err := cfg.normalizeHTTP(); err == nil || !strings.Contains(err.Error(), "literal URL path") {
		t.Fatalf("normalizeHTTP error = %v, want literal path rejection", err)
	}
}

func TestOAuthURLsRequireHTTPSHosts(t *testing.T) {
	t.Setenv("TEST_OAUTH_ID", "client")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	cfg := Empty()
	cfg.HTTP.Enabled = true
	cfg.HTTP.AuthMode = "oauth"
	cfg.HTTP.ResourceURL = "https:opaque-resource"
	cfg.HTTP.IntrospectionURL = "https://auth.example/introspect"
	cfg.HTTP.AuthorizationServers = []string{"https://auth.example"}
	cfg.HTTP.OAuthClientIDEnv = "TEST_OAUTH_ID"
	cfg.HTTP.OAuthClientSecretEnv = "TEST_OAUTH_SECRET"
	if err := cfg.normalizeHTTP(); err == nil || !strings.Contains(err.Error(), "resourceUrl") {
		t.Fatalf("normalizeHTTP error = %v, want resource URL rejection", err)
	}
}

func TestOpenSSHImportAndTemplate(t *testing.T) {
	dir := t.TempDir()
	sshConfig := filepath.Join(dir, "ssh-config")
	if err := os.WriteFile(sshConfig, []byte(`
Host bastion
  HostName jump.example.test
  User jump-user
  Port 2222
Host app
  HostName app.internal
  User deploy
  IdentityFile ~/.ssh/id_test
  ProxyJump bastion
`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeConfig(t, `
[defaults]
sshConfigFile = "`+strings.ReplaceAll(sshConfig, `\`, `\\`)+`"
importSSHHosts = ["app"]
approvalMode = "never"

[[profiles]]
name = "app"
sshConfigHost = "app"

[[profiles.commandTemplates]]
name = "show-release"
command = "cat {{path}}"
parameters = ["path"]
readOnly = true
`)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	app, err := cfg.Profile("app")
	if err != nil {
		t.Fatal(err)
	}
	if app.Host != "app.internal" || app.User != "deploy" || app.Auth != "key" || app.ProxyJump != "bastion" {
		t.Fatalf("imported app = %+v", app)
	}
	var bastion *Profile
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Name == "bastion" {
			bastion = &cfg.Profiles[i]
		}
	}
	if bastion == nil || !bastion.JumpOnly || bastion.Host != "jump.example.test" || bastion.Port != 2222 {
		t.Fatalf("imported bastion = %+v", bastion)
	}
	template, err := app.Template("show-release")
	if err != nil {
		t.Fatal(err)
	}
	command, err := template.Render(map[string]string{"path": "/tmp/it's safe"})
	if err != nil || command != `cat '/tmp/it'"'"'s safe'` {
		t.Fatalf("rendered command = %q, %v", command, err)
	}
}

func TestSSHFieldsPreservesWindowsPath(t *testing.T) {
	fields, err := sshFields(`IdentityFile C:\keys\id_ed25519`)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields[0] != "IdentityFile" || fields[1] != `C:\keys\id_ed25519` {
		t.Fatalf("sshFields = %#v", fields)
	}
}

func TestSSHFieldsSupportsEqualsSeparator(t *testing.T) {
	fields, err := sshFields(`HostName=server.example`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HostName", "=", "server.example"}
	if !slices.Equal(fields, want) {
		t.Fatalf("sshFields = %#v, want %#v", fields, want)
	}
}

func TestLiteralProxyJumpWithUserUsesHostOnly(t *testing.T) {
	profile, err := (&sshConfig{}).jumpProfile("jump-user@jump.example")
	if err != nil {
		t.Fatal(err)
	}
	if profile.User != "jump-user" || profile.Host != "jump.example" {
		t.Fatalf("jump profile = %+v", profile)
	}
}

func TestRootProfileRequiresExplicitOptIn(t *testing.T) {
	path := writeConfig(t, `
[[profiles]]
name = "dangerous"
host = "example.test"
user = "root"
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "allowRoot=true") {
		t.Fatalf("Load error = %v, want root opt-in error", err)
	}
}

func TestProxyJumpCycleRejected(t *testing.T) {
	path := writeConfig(t, `
[[profiles]]
name = "a"
host = "a.test"
user = "user"
proxyJump = "b"

[[profiles]]
name = "b"
host = "b.test"
user = "user"
proxyJump = "a"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("Load error = %v, want proxy jump cycle", err)
	}
}

func TestHTTPRequiresAuthAndTLSOffLoopback(t *testing.T) {
	t.Setenv("TEST_HTTP_TOKEN", "secret")
	path := writeConfig(t, `
[http]
enabled = true
listen = "0.0.0.0:8080"
authMode = "token"
tokenEnv = "TEST_HTTP_TOKEN"

[[profiles]]
name = "dev"
host = "example.test"
user = "deploy"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("Load error = %v, want TLS requirement", err)
	}
}

func TestHTTPOAuthConfiguration(t *testing.T) {
	t.Setenv("TEST_OAUTH_ID", "id")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	path := writeConfig(t, `
[http]
enabled = true
listen = "127.0.0.1:8080"
authMode = "oauth"
resourceUrl = "https://ssh.example/mcp"
authorizationServers = ["https://login.example"]
introspectionUrl = "https://login.example/introspect"
oauthClientIdEnv = "TEST_OAUTH_ID"
oauthClientSecretEnv = "TEST_OAUTH_SECRET"
requiredScopes = ["ssh:connect"]

[[profiles]]
name = "dev"
host = "example.test"
user = "deploy"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.AuthMode != "oauth" || len(cfg.HTTP.RequiredScopes) != 1 {
		t.Fatalf("HTTP config = %+v", cfg.HTTP)
	}
}

func TestExampleConfigurationLoads(t *testing.T) {
	examplePath := filepath.Join("..", "..", "config.example.toml")
	data, err := os.ReadFile(examplePath) //nolint:gosec // fixed repository test fixture
	if err != nil {
		t.Fatalf("read example configuration: %v", err)
	}
	// Repository files are normally checked out as 0644 on Unix, whereas a
	// live configuration must be private. Exercise the example through the
	// same owner-only fixture permissions expected from users.
	path := writeConfig(t, string(data))
	if _, err := Load(path); err != nil {
		t.Fatalf("example configuration does not load: %v", err)
	}
}
