package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterChainsAndRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := New(path, []string{`private-[0-9]+`})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Event{Action: "command", Command: "deploy --token=abc private-123"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Event{Action: "file", Target: "/tmp/x"}); err != nil {
		t.Fatal(err)
	}
	events, err := w.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Previous != events[0].Hash {
		t.Fatalf("events are not chained: %+v", events)
	}
	if strings.Contains(events[0].Command, "abc") || strings.Contains(events[0].Command, "private-123") {
		t.Fatalf("secret was not redacted: %q", events[0].Command)
	}
	data, _ := os.ReadFile(path) //nolint:gosec // path is rooted in t.TempDir
	data[len(data)/2] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // path is rooted in t.TempDir
		t.Fatal(err)
	}
	if err := w.Verify(); err == nil {
		t.Fatal("tampered audit log verified")
	}
}
