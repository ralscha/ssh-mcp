package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestIsCleanConnectionClose(t *testing.T) {
	closing := fmt.Errorf("wrapped: %w", &jsonrpc.Error{Code: -32004, Message: "server is closing"})
	if !isCleanConnectionClose(closing) {
		t.Fatal("server-closing error was not treated as clean")
	}
	if isCleanConnectionClose(errors.New("broken transport")) {
		t.Fatal("arbitrary error was treated as clean")
	}
}
