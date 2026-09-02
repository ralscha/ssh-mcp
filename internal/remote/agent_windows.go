//go:build windows

package remote

import (
	"context"
	"fmt"

	sshagent "github.com/xanzy/ssh-agent"
	"golang.org/x/crypto/ssh/agent"
)

// connectAgent uses native Windows agent discovery. Pageant is preferred when
// its window is present; otherwise the Windows OpenSSH named pipe is tried.
// Pageant communication uses its native shared-memory/WM_COPYDATA protocol, so
// SSH_AUTH_SOCK is neither required nor consulted on Windows.
func connectAgent(context.Context) (agent.Agent, func(), error) {
	client, connection, err := sshagent.New()
	if err != nil {
		return nil, func() {}, fmt.Errorf("detect Pageant or Windows OpenSSH agent: %w", err)
	}
	cleanup := func() {
		if connection != nil {
			_ = connection.Close()
		}
	}
	return client, cleanup, nil
}
