package mcphttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestStaticBearerAndOrigin(t *testing.T) {
	t.Setenv("TEST_SSH_MCP_TOKEN", "correct-secret")
	cfg := config.Empty()
	cfg.HTTP.Path = "/mcp"
	cfg.HTTP.AuthMode = "token"
	cfg.HTTP.TokenEnv = "TEST_SSH_MCP_TOKEN"
	cfg.HTTP.AllowedOrigins = []string{"https://client.example"}
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	handler := Handler(cfg, server)

	request := httptest.NewRequest(http.MethodPost, "http://server.example/mcp", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("without token status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "http://server.example/mcp", nil)
	request.Header.Set("Authorization", "Bearer correct-secret")
	request.Header.Set("Origin", "https://evil.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d", response.Code)
	}
}

func TestAuthorizedStreamableHTTPHandshake(t *testing.T) {
	t.Setenv("TEST_SSH_MCP_TOKEN", "correct-secret")
	cfg := config.Empty()
	cfg.HTTP.Path = "/mcp"
	cfg.HTTP.AuthMode = "token"
	cfg.HTTP.TokenEnv = "TEST_SSH_MCP_TOKEN"
	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1"}, nil)
	httpServer := httptest.NewServer(Handler(cfg, server))
	defer httpServer.Close()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		request.Header.Set("Authorization", "Bearer correct-secret")
		return http.DefaultTransport.RoundTrip(request)
	})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL + "/mcp", HTTPClient: client, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if got := session.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("protocol version = %q, want 2026-07-28", got)
	}
	if _, err := session.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	t.Setenv("TEST_SSH_MCP_TOKEN", "correct-secret")
	cfg := config.Empty()
	cfg.HTTP.AuthMode = "token"
	cfg.HTTP.TokenEnv = "TEST_SSH_MCP_TOKEN"
	cfg.HTTP.MaxRequestBytes = 16
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("x", 17)))
	request.Header.Set("Authorization", "Bearer correct-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()
	Handler(cfg, server).ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
}

func TestOAuthMetadataUsesResourcePath(t *testing.T) {
	cfg := config.Empty()
	cfg.HTTP.AuthMode = "oauth"
	cfg.HTTP.ResourceURL = "https://ssh.example/mcp"
	cfg.HTTP.AuthorizationServers = []string{"https://auth.example"}
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	handler := Handler(cfg, server)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status = %d; body=%s", response.Code, response.Body.String())
	}
	if got := protectedResourceMetadataPath(cfg.HTTP.ResourceURL); got != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("metadata path = %q", got)
	}
	auth := &authorizer{cfg: cfg}
	if got := auth.metadataURL(); got != "https://ssh.example/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("metadata URL = %q", got)
	}
}

func TestOAuthIntrospectionScopesAndAudience(t *testing.T) {
	t.Setenv("TEST_OAUTH_ID", "client")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	introspection := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client" || secret != "secret" {
			http.Error(w, "bad client", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("token") != "access-token" {
			http.Error(w, "bad token", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "scope": "ssh:read ssh:write", "aud": []string{"https://ssh.example/mcp"},
		})
	}))
	defer introspection.Close()
	cfg := config.Empty()
	cfg.HTTP.AuthMode = "oauth"
	cfg.HTTP.IntrospectionURL = introspection.URL
	cfg.HTTP.ResourceURL = "https://ssh.example/mcp"
	cfg.HTTP.OAuthClientIDEnv = "TEST_OAUTH_ID"
	cfg.HTTP.OAuthClientSecretEnv = "TEST_OAUTH_SECRET"
	auth := &authorizer{cfg: cfg, client: introspection.Client(), cache: make(map[string]introspectionResult)}
	result, err := auth.introspect(t.Context(), "access-token")
	if err != nil || !result.Active || !result.Scopes["ssh:write"] {
		t.Fatalf("introspection result = %+v, %v", result, err)
	}
}
