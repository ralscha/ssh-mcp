//go:build windows

package remote

import (
	"context"
	"strings"
	"testing"
)

func TestWindowsAgentDiscovery(t *testing.T) {
	client, cleanup, err := connectAgent(context.Background())
	if err != nil {
		// Having no agent running is a valid test-machine state. The important
		// behavior is that native discovery ran and returned an actionable error.
		if !strings.Contains(err.Error(), "Pageant or Windows OpenSSH agent") {
			t.Fatalf("connectAgent error = %v", err)
		}
		return
	}
	defer cleanup()
	keys, err := client.List()
	if err != nil {
		t.Fatalf("list keys from discovered Windows agent: %v", err)
	}
	t.Logf("discovered Windows SSH agent with %d loaded key(s)", len(keys))
}
