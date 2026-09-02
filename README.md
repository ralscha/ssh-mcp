# ssh-mcp

A small, security-conscious [Model Context Protocol](https://modelcontextprotocol.io/) server that gives MCP clients controlled SSH access to configured hosts. It uses the official Go MCP SDK, `x/crypto/ssh`, and SFTP.

The server supports:

- reusable SSH connections with password, private-key, SSH-agent, or native Windows Pageant authentication;
- optional selection of one Pageant/agent key by SHA-256 fingerprint;
- OpenSSH config imports and chained `ProxyJump`/bastion connections;
- strict `known_hosts` verification or an exact SHA-256 host-key pin;
- policy-gated read-only, general, and shell-quoted template commands;
- human approval for risky operations through MCP elicitation/multi-round-trip input;
- command timeouts, cancellation, bounded output, optional PTY, and stdin;
- server-enforced SFTP timeouts and bounded HTTP request bodies;
- persistent background jobs, progress notifications, and the stable MCP Tasks extension;
- structured, bounded SFTP listing, stat, range reads, checksums, atomic writes, and guarded unified patches;
- structured directory creation, rename, and non-recursive removal;
- tamper-evident, redacted JSONL auditing;
- stdio plus authenticated Streamable HTTP transport, including OAuth introspection mode.

The server deliberately does not provide an interactive terminal. Commands remain bounded requests or cancellable background jobs so policy, auditing, and output limits continue to apply. Root logins and profiles without a command allowlist fail closed unless their explicit opt-ins are set.

## Installation

Download a release archive for your platform from the repository's Releases page, verify it against `checksums.txt`, and place `ssh-mcp` (or `ssh-mcp.exe`) on your `PATH`.

## Build

Go 1.27 or newer is expected by this module:

```powershell
go build -o ssh-mcp.exe ./cmd/ssh-mcp
go test ./...
```

On Linux or macOS, use `-o ssh-mcp` instead.

Run `ssh-mcp --version` to verify the installed build. Version 1.0.0 release archives contain the executable, this README, the license, and the example configuration.

## Configure

Copy [`config.example.toml`](config.example.toml) to the platform config path:

| Platform | Default path |
|---|---|
| Linux | `~/.config/ssh-mcp/config.toml` |
| macOS | `~/Library/Application Support/ssh-mcp/config.toml` |
| Windows | `%AppData%\ssh-mcp\config.toml` |

You can also pass `--config PATH`. On Unix, the config must not be readable or writable by group/others; use `chmod 600`.

Passwords and private-key passphrases are read only from environment variables. For a profile named `prod-web`, resolution is:

1. `SSH_MCP_PROD_WEB_PASSWORD`, then `SSH_MCP_PASSWORD`;
2. `SSH_MCP_PROD_WEB_KEY_PASSPHRASE`, then `SSH_MCP_KEY_PASSPHRASE`.

For agent authentication, set `auth = "agent"`. On Linux and macOS the server uses `SSH_AUTH_SOCK`. On Windows it automatically uses native PuTTY Pageant when Pageant is running, with no bridge or `SSH_AUTH_SOCK` required; otherwise it tries the Windows OpenSSH agent at `\\.\pipe\openssh-ssh-agent`. Pageant must already be running with at least one suitable key loaded.

If an agent contains many keys, set `agentKeyFingerprint = "SHA256:..."` on the profile. Only that key is offered, avoiding `MaxAuthTries` failures. `diagnose-connection` lists the loaded public-key fingerprints and reports which one is selected; it never returns private material.

### OpenSSH config and jump hosts

Set `sshConfigHost` on a profile to fill missing `HostName`, `User`, `Port`, `IdentityFile`, and `ProxyJump` values from `~/.ssh/config`:

```toml
[[profiles]]
name = "production"
sshConfigHost = "prod-web"
```

Alternatively, `defaults.importSSHHosts = ["prod-web", "staging"]` creates profiles for exact aliases. A referenced `ProxyJump` alias is imported automatically as a jump-only profile: it can carry the SSH connection but cannot be targeted by MCP tools. Explicit TOML values override imported OpenSSH values. `Include` directives and wildcard/negated `Host` patterns are supported; conditional `Match` blocks are intentionally ignored. For multiple hops, chain configured profiles with `proxyJump` rather than using a comma-separated OpenSSH value.

Host-key verification is strict by default. The server uses `knownHostsFile`, normally `~/.ssh/known_hosts`, unless `trustedHostKey` pins an exact `SHA256:...` fingerprint. `hostKeyMode = "insecure"` and per-profile `insecureSkipHostKey = true` exist for isolated test hosts and emit a warning; do not use them for real systems.

## MCP client setup

Build the executable, then add it to your MCP client's configuration:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "C:\\path\\to\\ssh-mcp.exe",
      "args": ["--config", "C:\\path\\to\\config.toml"],
      "env": {
        "SSH_MCP_DEV_KEY_PASSPHRASE": "optional-passphrase"
      }
    }
  }
}
```

If the default config file does not exist, the MCP handshake and `tools/list` still work, but every tool call returns a clear unconfigured error.

## Tools

| Tool | Purpose |
|---|---|
| `list-connections` | List profiles and lazy connection state. |
| `read-command` | Run one conservative, allowlisted read-only command without shell operators. |
| `run-command` | Run a command after built-in and configured policy checks. |
| `list-command-templates` | List narrowly scoped operations configured for a profile. |
| `run-command-template` | Render a template with shell-quoted arguments, then apply normal policy. |
| `diagnose-connection` | Test DNS, direct/proxied TCP, agent keys, host key, and authentication separately. |
| `start-command` | Start a persistent, cancellable background command. |
| `job-status`, `job-output`, `cancel-job` | Poll and manage a background job by its unguessable ID on clients without Tasks support. |
| `sftp-upload` | Atomically upload UTF-8 or base64 content. Mutating; denied on read-only profiles. |
| `sftp-download` | Download a bounded file as UTF-8 or base64. |
| `sftp-list`, `sftp-stat` | Inspect directories and path metadata. |
| `sftp-read` | Read a bounded file byte range. |
| `sftp-checksum` | Calculate a bounded remote file's SHA-256. |
| `sftp-write` | Alias for atomic `sftp-upload`. |
| `sftp-apply-patch` | Apply a unified diff after checking the current SHA-256, then atomically replace the file. |
| `sftp-mkdir` | Create a directory, optionally including missing parents. |
| `sftp-rename` | Rename a path, with explicit opt-in for destination replacement. |
| `sftp-remove` | Remove one file, symlink, or empty directory; recursive deletion is not supported. |
| `audit-list`, `audit-verify` | Read redacted events and verify the hash chain. |

`read-command` recognizes common inspection commands such as `ls`, `cat`, `grep`, `ps`, `stat`, `systemctl status/show`, `docker ps/logs/inspect`, and `kubectl get/logs/describe`. It rejects shell operators and redirection. Git is intentionally excluded because repository configuration can invoke helper programs and some nominally observational Git commands can update the index; expose a deliberately constrained Git command template if needed.

`run-command` is broader, but always blocks a narrow catastrophic set such as filesystem formatting, `dd ... of=/dev/...`, root-recursive removal, shutdown/reboot, pipe-to-shell installers, fork bombs, and destructive root permission changes. These rules reduce accidents; they are not a shell sandbox. A profile must configure at least one `allowedCommands` expression before `run-command` or `start-command` can be used. Setting `allowUnrestrictedCommands = true` bypasses only that allowlist requirement and should be reserved for isolated, trusted environments; built-in and configured deny rules still apply.

When `allowedCommands` is non-empty, a command must match at least one expression. Global and per-profile `denyCommands` are applied first. Invalid regular expressions stop startup.

Command templates use `{{parameter}}` placeholders. Every supplied value is POSIX-shell quoted, undeclared or missing arguments are rejected, and the rendered command still passes through the same deny/allow and catastrophic-command checks. Set `readOnly = true` only for a genuinely non-mutating template; `requiresApproval = true` forces confirmation.

### Approvals

`approvalMode` can be set globally or per profile:

- `risky` (default) requests confirmation for privilege escalation, service/package/firewall changes, deletion, permission changes, selected Git/container/Kubernetes mutations, shell redirection, file replacement, and patching;
- `always` requests confirmation for every mutating action;
- `never` relies on server policy without interactive confirmation.

Current MCP sessions receive an `InputRequests` approval and automatically retry after the user answers. Older sessions use elicitation through the SDK compatibility flow. Declined, missing, expired, modified, or unsupported approvals fail closed. Catastrophic commands remain blocked and cannot be approved.

### Background jobs and MCP Tasks

`start-command` returns a normal job object to ordinary clients. Clients that declare `io.modelcontextprotocol/tasks` in their per-request extension capabilities receive a stable 2026-07-28 `CreateTaskResult` instead and can call `tasks/get`, `tasks/cancel`, and `tasks/update`. The server only returns the polymorphic Task result after explicit client opt-in.

Job metadata and bounded output are persisted to `jobStateFile`; command strings are intentionally not persisted. Running jobs are marked failed after a server restart because SSH cannot reattach to an already detached process. Completed handles remain pollable until `jobRetentionMs` expires. Clients must retain the job ID returned by `start-command`; there is intentionally no global job-list tool because a list can disclose other callers' task handles. Non-Tasks callers with a progress token receive start and terminal progress notifications.

SFTP `mode` is a JSON integer: Unix `0600` is decimal `384`, and `0644` is decimal `420`. Omit it for `0600`.

`sftp-apply-patch` requires `expectedSha256`, normally obtained from `sftp-checksum`. The checksum is rechecked immediately before upload. SFTP has no portable compare-and-swap primitive, so another writer can still race the final rename; use remote OS permissions or a command template with application-specific locking when strict cross-process serialization is required. Patch targets must be regular UTF-8 files; symlinks, directories, and special files are rejected.

Writes use a sibling temporary file, request an SFTP `fsync` when supported, and use the OpenSSH POSIX rename extension for atomic replacement. If the destination exists and that extension is unavailable, the write fails instead of silently degrading to a non-atomic replacement.

## Audit log

Set `defaults.auditLog` to enable append-only JSONL auditing. Events include the profile, action, redacted command or target, authorization decision, outcome, duration, exit code, and transferred byte count. Each event hashes its content and the previous event hash; startup and `audit-verify` reject a modified chain. The log is forced to owner-only permissions where the platform supports them.

Built-in redaction covers common password/token/secret assignments, bearer tokens, and PEM private keys. Add installation-specific regular expressions with `defaults.auditRedact`. Avoid putting secrets directly in commands in the first place; use the server's environment-based credential resolution.

## Streamable HTTP and OAuth

Stdio is the default. Set `[http].enabled = true` to serve stateless Streamable HTTP at `listen` plus `path`, including MCP revision `2026-07-28`. `authMode = "token"` compares the bearer credential against `tokenEnv` in constant time. Non-loopback listeners require a TLS certificate and key, and browser origins must be same-origin or explicitly listed in `allowedOrigins`. Requests larger than `maxRequestBytes` are rejected with HTTP 413.

For a shared deployment, `authMode = "oauth"`:

- publishes OAuth protected-resource metadata at the RFC 9728 path derived from `resourceUrl` (for example `/.well-known/oauth-protected-resource/mcp`) with the pathless endpoint retained for compatibility;
- challenges unauthenticated requests with `WWW-Authenticate` and `resource_metadata`;
- validates access tokens through RFC 7662 introspection;
- verifies expiry, audience/resource, and every configured required scope;
- caches only a SHA-256 token identifier and the short-lived validation result, never the token itself.

The OAuth introspection client ID and secret come from `oauthClientIdEnv` and `oauthClientSecretEnv`. The authorization server, resource URL, and introspection endpoint must use HTTPS.

## Security notes

- Avoid root SSH accounts.
- If root access is unavoidable, it must be acknowledged with `allowRoot = true`; use a dedicated profile with a very narrow allowlist and approval mode `always`.
- Prefer a dedicated remote user with OS-level permissions matching the task.
- Keep strict host-key verification enabled.
- Use a narrow `allowedCommands` list for production profiles.
- Prefer command templates over arbitrary `run-command` access.
- Mark inspection-only profiles with `readOnly = true`; this disables `run-command` and uploads.
- Keep `approvalMode = "risky"` or `always` unless the MCP client cannot present approvals.
- Keep HTTP on loopback unless TLS and OAuth are configured.
- OAuth scopes authorize the server as a whole; for tenant- or user-specific profile isolation, run separate instances with separate configuration, audit, and job-state files.
- Run only one server process per `auditLog` and `jobStateFile`; these files use atomic replacement and process-local synchronization, not cross-process locking.
- MCP tool annotations are hints to clients, not access controls. Enforcement happens in the server before opening an SSH channel.

## Development

```powershell
gofmt -w cmd internal
go vet ./...
go test ./...
go build ./cmd/ssh-mcp
```

The repository also includes the same Taskfile, GoReleaser, lint configuration, and test/release workflow layout used by `jira-mcp`. Run `task check` for the local release gate.

## License

MIT - see [`LICENSE`](LICENSE).
