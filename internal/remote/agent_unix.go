//go:build !windows

package remote

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func connectAgent(ctx context.Context) (agent.Agent, func(), error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, func() {}, fmt.Errorf("SSH_AUTH_SOCK is not set")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, func() {}, fmt.Errorf("connect to SSH_AUTH_SOCK: %w", err)
	}
	return agent.NewClient(connection), func() { _ = connection.Close() }, nil
}
