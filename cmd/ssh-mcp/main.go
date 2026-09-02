package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/config"
	"ssh-mcp/internal/mcphttp"
	"ssh-mcp/internal/remote"
	app "ssh-mcp/internal/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("ssh-mcp: %v", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("ssh-mcp", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	defaultConfig, err := config.DefaultPath()
	if err != nil {
		return err
	}
	configPath := flags.String("config", defaultConfig, "path to TOML configuration")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *showVersion {
		fmt.Println("ssh-mcp " + app.ServerVersion())
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && *configPath == defaultConfig {
			cfg = config.Empty()
			log.Printf("starting unconfigured; expected config at %s", defaultConfig)
		} else {
			return err
		}
	}
	if cfg.Defaults.HostKeyMode == "insecure" {
		log.Printf("WARNING: host-key verification is disabled globally")
	}
	for i := range cfg.Profiles {
		if cfg.Profiles[i].InsecureSkipHostKey {
			log.Printf("WARNING: host-key verification is disabled for profile %q", cfg.Profiles[i].Name)
		}
	}

	manager := remote.NewManager(cfg)
	defer func() {
		if closeErr := manager.Close(); closeErr != nil {
			log.Printf("close SSH connections: %v", closeErr)
		}
	}()
	service, err := app.New(cfg, manager)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.HTTP.Enabled {
		log.Printf("serving MCP Streamable HTTP on %s%s", cfg.HTTP.Listen, cfg.HTTP.Path)
		if err := mcphttp.Serve(ctx, cfg, service.MCPServer()); err != nil {
			return fmt.Errorf("serve MCP over HTTP: %w", err)
		}
		return nil
	}
	if err := service.MCPServer().Run(ctx, &mcp.StdioTransport{}); err != nil {
		if !errors.Is(err, context.Canceled) && !isCleanConnectionClose(err) {
			return fmt.Errorf("serve MCP over stdio: %w", err)
		}
	}
	return nil
}

func isCleanConnectionClose(err error) bool {
	var rpcError *jsonrpc.Error
	// The SDK wraps stdin EOF as its private server-closing JSON-RPC error;
	// jsonrpc.Error exposes the code even though the sentinel is internal.
	return errors.As(err, &rpcError) && (rpcError.Code == -32004 || rpcError.Code == -32003)
}
