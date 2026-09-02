// Package mcphttp exposes authenticated MCP Streamable HTTP transport.
package mcphttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"ssh-mcp/internal/config"
)

const maxIntrospectionCacheEntries = 1024

type introspectionResult struct {
	Active bool
	Scopes map[string]bool
	Expiry time.Time
}

type authorizer struct {
	cfg    *config.Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]introspectionResult
}

// Handler builds an MCP handler with origin checks and either constant-time
// static bearer authentication or OAuth 2.0 token introspection.
func Handler(cfg *config.Config, server *mcp.Server) http.Handler {
	stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true,
	})
	auth := &authorizer{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}, cache: make(map[string]introspectionResult)}
	mux := http.NewServeMux()
	metadataPath := protectedResourceMetadataPath(cfg.HTTP.ResourceURL)
	mux.HandleFunc(metadataPath, auth.metadata)
	if metadataPath != "/.well-known/oauth-protected-resource" {
		// Keep the pathless endpoint for older clients while serving the RFC 9728
		// path-derived endpoint used by current MCP clients.
		mux.HandleFunc("/.well-known/oauth-protected-resource", auth.metadata)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}
	})
	mux.Handle(cfg.HTTP.Path, auth.middleware(limitRequestBody(cfg.HTTP.MaxRequestBytes, stream)))
	return securityHeaders(mux)
}

func Serve(ctx context.Context, cfg *config.Config, server *mcp.Server) error {
	httpServer := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           Handler(cfg, server),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		if cfg.HTTP.TLSCertFile != "" {
			errCh <- httpServer.ListenAndServeTLS(cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile)
		} else {
			errCh <- httpServer.ListenAndServe()
		}
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		return nil
	}
}

func (a *authorizer) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.originAllowed(r) {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			a.unauthorized(w, "invalid_token", "a bearer token is required")
			return
		}
		if a.cfg.HTTP.AuthMode == "oauth" {
			result, err := a.introspect(r.Context(), token)
			if err != nil {
				http.Error(w, "authorization service unavailable", http.StatusServiceUnavailable)
				return
			}
			if !result.Active {
				a.unauthorized(w, "invalid_token", "the access token is inactive")
				return
			}
			var missing []string
			for _, scope := range a.cfg.HTTP.RequiredScopes {
				if !result.Scopes[scope] {
					missing = append(missing, scope)
				}
			}
			if len(missing) > 0 {
				w.Header().Set("WWW-Authenticate", a.oauthChallenge("insufficient_scope", "the access token lacks required scopes"))
				http.Error(w, "access token lacks required scopes", http.StatusForbidden)
				return
			}
		} else {
			want := os.Getenv(a.cfg.HTTP.TokenEnv)
			if len(token) != len(want) || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
				a.unauthorized(w, "invalid_token", "the bearer token is invalid")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *authorizer) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if slices.Contains(a.cfg.HTTP.AllowedOrigins, origin) {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host) && ((parsed.Scheme == "https" && r.TLS != nil) || (parsed.Scheme == "http" && r.TLS == nil))
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func (a *authorizer) introspect(ctx context.Context, token string) (introspectionResult, error) {
	sum := sha256.Sum256([]byte(token))
	cacheKey := hex.EncodeToString(sum[:])
	now := time.Now()
	a.mu.Lock()
	if cached, ok := a.cache[cacheKey]; ok && now.Before(cached.Expiry) {
		a.mu.Unlock()
		return cached, nil
	}
	a.mu.Unlock()
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.HTTP.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return introspectionResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(os.Getenv(a.cfg.HTTP.OAuthClientIDEnv), os.Getenv(a.cfg.HTTP.OAuthClientSecretEnv))
	response, err := a.client.Do(req)
	if err != nil {
		return introspectionResult{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return introspectionResult{}, fmt.Errorf("introspection returned HTTP %d", response.StatusCode)
	}
	var body struct {
		Active bool  `json:"active"`
		Scope  any   `json:"scope"`
		Aud    any   `json:"aud"`
		Exp    int64 `json:"exp"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&body); err != nil {
		return introspectionResult{}, fmt.Errorf("decode introspection response: %w", err)
	}
	result := introspectionResult{Active: body.Active, Scopes: stringSet(body.Scope), Expiry: time.Now().Add(30 * time.Second)}
	if body.Exp > 0 {
		expiry := time.Unix(body.Exp, 0)
		if expiry.Before(result.Expiry) {
			result.Expiry = expiry
		}
		if time.Now().After(expiry) {
			result.Active = false
		}
	}
	wantAudience := a.cfg.HTTP.Audience
	if wantAudience == "" {
		wantAudience = a.cfg.HTTP.ResourceURL
	}
	if wantAudience != "" && !stringSet(body.Aud)[wantAudience] {
		result.Active = false
	}
	a.mu.Lock()
	for key, cached := range a.cache {
		if !now.Before(cached.Expiry) {
			delete(a.cache, key)
		}
	}
	if len(a.cache) >= maxIntrospectionCacheEntries {
		var oldestKey string
		var oldestExpiry time.Time
		for key, cached := range a.cache {
			if oldestKey == "" || cached.Expiry.Before(oldestExpiry) {
				oldestKey, oldestExpiry = key, cached.Expiry
			}
		}
		delete(a.cache, oldestKey)
	}
	a.cache[cacheKey] = result
	a.mu.Unlock()
	return result, nil
}

func stringSet(value any) map[string]bool {
	set := make(map[string]bool)
	switch value := value.(type) {
	case string:
		for item := range strings.FieldsSeq(value) {
			set[item] = true
		}
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok {
				set[text] = true
			}
		}
	}
	return set
}

func (a *authorizer) metadata(w http.ResponseWriter, r *http.Request) {
	if a.cfg.HTTP.AuthMode != "oauth" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(oauthex.ProtectedResourceMetadata{
			Resource: a.cfg.HTTP.ResourceURL, AuthorizationServers: a.cfg.HTTP.AuthorizationServers,
			ScopesSupported: a.cfg.HTTP.RequiredScopes, BearerMethodsSupported: []string{"header"}, ResourceName: "ssh-mcp",
		})
	}
}

func (a *authorizer) unauthorized(w http.ResponseWriter, code, description string) {
	if a.cfg.HTTP.AuthMode == "oauth" {
		w.Header().Set("WWW-Authenticate", a.oauthChallenge(code, description))
	} else {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ssh-mcp", error="`+escapeAuthParam(code)+`", error_description="`+escapeAuthParam(description)+`"`)
	}
	http.Error(w, description, http.StatusUnauthorized)
}

func (a *authorizer) oauthChallenge(code, description string) string {
	parts := []string{
		`Bearer error="` + escapeAuthParam(code) + `"`,
		`error_description="` + escapeAuthParam(description) + `"`,
		`resource_metadata="` + escapeAuthParam(a.metadataURL()) + `"`,
	}
	if len(a.cfg.HTTP.RequiredScopes) > 0 {
		parts = append(parts, `scope="`+escapeAuthParam(strings.Join(a.cfg.HTTP.RequiredScopes, " "))+`"`)
	}
	return strings.Join(parts, ", ")
}

func (a *authorizer) metadataURL() string {
	if resource, err := url.Parse(a.cfg.HTTP.ResourceURL); err == nil && resource.IsAbs() {
		return resource.Scheme + "://" + resource.Host + protectedResourceMetadataPath(a.cfg.HTTP.ResourceURL)
	}
	return "/.well-known/oauth-protected-resource"
}

func protectedResourceMetadataPath(resourceURL string) string {
	resource, err := url.Parse(resourceURL)
	if err != nil || strings.Trim(resource.Path, "/") == "" {
		return "/.well-known/oauth-protected-resource"
	}
	return "/.well-known/oauth-protected-resource/" + strings.TrimLeft(resource.EscapedPath(), "/")
}

func escapeAuthParam(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func limitRequestBody(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maxBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
