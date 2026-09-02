// Package audit writes append-only, hash-chained JSONL security events.
package audit

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Profile     string    `json:"profile,omitempty"`
	Command     string    `json:"command,omitempty"`
	CommandHash string    `json:"commandHash,omitempty"`
	Target      string    `json:"target,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
	DurationMS  int64     `json:"durationMs,omitempty"`
	Bytes       int64     `json:"bytes,omitempty"`
	ExitCode    *int      `json:"exitCode,omitempty"`
	Error       string    `json:"error,omitempty"`
	Previous    string    `json:"previousHash,omitempty"`
	Hash        string    `json:"hash"`
}

type Writer struct {
	mu        sync.Mutex
	path      string
	previous  string
	redactors []*regexp.Regexp
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|passphrase|token|secret|api[_-]?key)(\s*[=:]\s*)([^\s;&|]+)`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----`),
}

func New(path string, patterns []string) (*Writer, error) {
	w := &Writer{path: path}
	for _, source := range patterns {
		re, err := regexp.Compile(source)
		if err != nil {
			return nil, fmt.Errorf("defaults.auditRedact contains invalid regular expression %q: %w", source, err)
		}
		w.redactors = append(w.redactors, re)
	}
	if path == "" {
		return w, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	if err := w.verifyLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) Enabled() bool { return w != nil && w.path != "" }

func (w *Writer) Append(event Event) error {
	if !w.Enabled() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if event.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		event.ID = id
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Command = w.redact(event.Command)
	event.Target = w.redact(event.Target)
	event.Error = w.redact(event.Error)
	if event.Command != "" && event.CommandHash == "" {
		sum := sha256.Sum256([]byte(event.Command))
		event.CommandHash = hex.EncodeToString(sum[:])
	}
	event.Previous = w.previous
	event.Hash = ""
	unsigned, err := json.Marshal(event)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(unsigned)
	event.Hash = hex.EncodeToString(sum[:])
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("secure audit log permissions: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("append audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	w.previous = event.Hash
	return nil
}

func (w *Writer) Read(limit int) ([]Event, error) {
	if !w.Enabled() {
		return nil, errors.New("audit logging is disabled")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	events, _, err := readAndVerify(w.path)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func (w *Writer) Verify() error {
	if !w.Enabled() {
		return errors.New("audit logging is disabled")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.verifyLocked()
}

func (w *Writer) verifyLocked() error {
	_, previous, err := readAndVerify(w.path)
	if errors.Is(err, os.ErrNotExist) {
		w.previous = ""
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify audit log: %w", err)
	}
	w.previous = previous
	return nil
}

func readAndVerify(path string) ([]Event, string, error) {
	f, err := os.Open(path) //nolint:gosec // path is the administrator-configured audit log
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	var events []Event
	previous := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, "", fmt.Errorf("line %d is invalid JSON: %w", line, err)
		}
		if event.Previous != previous {
			return nil, "", fmt.Errorf("line %d previous hash mismatch", line)
		}
		want := event.Hash
		event.Hash = ""
		unsigned, _ := json.Marshal(event)
		sum := sha256.Sum256(unsigned)
		got := hex.EncodeToString(sum[:])
		if want == "" || got != want {
			return nil, "", fmt.Errorf("line %d hash mismatch", line)
		}
		event.Hash = want
		previous = want
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	return events, previous, nil
}

func (w *Writer) redact(value string) string {
	if value == "" {
		return ""
	}
	for _, re := range secretPatterns {
		if re == secretPatterns[0] {
			value = re.ReplaceAllString(value, `$1$2[REDACTED]`)
		} else {
			value = re.ReplaceAllString(value, "[REDACTED]")
		}
	}
	for _, re := range w.redactors {
		value = re.ReplaceAllString(value, "[REDACTED]")
	}
	return value
}

func randomID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate audit event ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
