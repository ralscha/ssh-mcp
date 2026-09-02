package policy

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"ssh-mcp/internal/config"
)

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|[;&|]\s*)(sudo\s+)?(?:shutdown|reboot|poweroff|halt)(?:\s|$)`),
	regexp.MustCompile(`(?i)(^|[;&|]\s*)(sudo\s+)?mkfs(?:\.|\s|$)`),
	regexp.MustCompile(`(?i)\bdd\s+[^;&|]*\bof\s*=\s*/dev/`),
	regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--\s+)?/(?:\s|$|\*)`),
	regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b`),
	regexp.MustCompile(`(?i)>+\s*(?:/etc/(?:cron|systemd)|[^\s]*authorized_keys)`),
	regexp.MustCompile(`(?i)\biptables\s+-F(?:\s|$)`),
	regexp.MustCompile(`(?i)\bchmod\s+(?:-[Rr]\s+)?777\s+/(?:\s|$)`),
	regexp.MustCompile(`(?i)\bchown\s+(?:-[Rr]\s+)?\S+\s+/(?:\s|$)`),
	regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`),
}

var riskyCommandPatterns = []struct {
	reason string
	re     *regexp.Regexp
}{
	{"uses privilege escalation", regexp.MustCompile(`(?i)(^|[;&|]\s*)sudo(?:\s|$)`)},
	{"changes service state", regexp.MustCompile(`(?i)\b(?:systemctl|service)\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b`)},
	{"installs or removes packages", regexp.MustCompile(`(?i)\b(?:apt(?:-get)?|dnf|yum|zypper|pacman|apk|brew|winget|choco)\s+(?:install|remove|purge|upgrade|update|add|del)\b`)},
	{"changes firewall rules", regexp.MustCompile(`(?i)\b(?:iptables|nft|ufw|firewall-cmd)\b`)},
	{"deletes files", regexp.MustCompile(`(?i)(^|[;&|]\s*)(?:/\S*/)?(?:rm|rmdir|unlink)\b`)},
	{"changes ownership or permissions", regexp.MustCompile(`(?i)(^|[;&|]\s*)(?:sudo\s+)?(?:chmod|chown|chgrp)\b`)},
	{"changes remote source control", regexp.MustCompile(`(?i)\bgit\s+(?:push|reset|clean|rebase|merge)\b`)},
	{"changes containers", regexp.MustCompile(`(?i)\b(?:docker|podman)\s+(?:rm|rmi|prune|stop|restart|kill|run|compose\s+(?:up|down))\b`)},
	{"changes cluster resources", regexp.MustCompile(`(?i)\bkubectl\s+(?:apply|create|delete|edit|patch|replace|scale|rollout)\b`)},
	{"writes through shell redirection", regexp.MustCompile(`(?:^|[^<])>{1,2}\s*\S+`)},
}

var readOnlyCommands = map[string]bool{
	"cat": true, "cut": true, "df": true, "du": true, "free": true,
	"grep": true, "head": true, "id": true, "ls": true, "printf": true,
	"ps": true, "pwd": true, "rg": true, "stat": true, "tail": true,
	"uname": true, "uptime": true, "wc": true, "who": true, "whoami": true,
}

var readOnlySubcommands = map[string]map[string]bool{
	"docker":    {"images": true, "inspect": true, "logs": true, "ps": true, "stats": true, "version": true},
	"systemctl": {"is-active": true, "is-enabled": true, "list-units": true, "show": true, "status": true},
	"kubectl":   {"api-resources": true, "describe": true, "get": true, "logs": true, "version": true},
}

// Engine applies the built-in safety rules and configured profile policy.
type Engine struct {
	globalDeny []*regexp.Regexp
	allow      map[string][]*regexp.Regexp
	deny       map[string][]*regexp.Regexp
}

func New(cfg *config.Config) (*Engine, error) {
	e := &Engine{
		allow: make(map[string][]*regexp.Regexp),
		deny:  make(map[string][]*regexp.Regexp),
	}
	var err error
	if e.globalDeny, err = compile("defaults.denyCommands", cfg.Defaults.DenyCommands); err != nil {
		return nil, err
	}
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		if e.allow[p.Name], err = compile(fmt.Sprintf("profile %q allowedCommands", p.Name), p.AllowedCommands); err != nil {
			return nil, err
		}
		if e.deny[p.Name], err = compile(fmt.Sprintf("profile %q denyCommands", p.Name), p.DenyCommands); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func compile(field string, patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, source := range patterns {
		re, err := regexp.Compile(source)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid regular expression %q: %w", field, source, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// AuthorizeCommand validates command and enforces the selected profile's rules.
// readOnlyTool additionally requires a command from the deliberately narrow
// read-only allowlist.
func (e *Engine) AuthorizeCommand(cfg *config.Config, p *config.Profile, command string, readOnlyTool bool) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("command cannot be empty")
	}
	if strings.IndexByte(command, 0) >= 0 {
		return fmt.Errorf("command contains a NUL byte")
	}
	max := cfg.CommandMaxChars(p)
	if max > 0 && len(command) > max {
		return fmt.Errorf("command is %d bytes; profile limit is %d", len(command), max)
	}
	for _, re := range forbiddenPatterns {
		if re.MatchString(command) {
			return fmt.Errorf("command is blocked by a built-in safety rule")
		}
	}
	if catastrophicRemove(command) {
		return fmt.Errorf("command is blocked by a built-in safety rule")
	}
	for _, re := range e.globalDeny {
		if re.MatchString(command) {
			return fmt.Errorf("command is blocked by defaults.denyCommands rule %q", re.String())
		}
	}
	for _, re := range e.deny[p.Name] {
		if re.MatchString(command) {
			return fmt.Errorf("command is blocked by profile denyCommands rule %q", re.String())
		}
	}
	if allowed := e.allow[p.Name]; len(allowed) > 0 {
		matched := false
		for _, re := range allowed {
			if re.MatchString(command) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("command does not match any profile allowedCommands rule")
		}
	}
	if readOnlyTool {
		if !isReadOnlyCommand(command) {
			return fmt.Errorf("read-command only accepts a single allowlisted read-only command without shell operators")
		}
		return nil
	}
	if p.ReadOnly {
		return fmt.Errorf("profile %q is read-only; use read-command", p.Name)
	}
	return nil
}

// AuthorizeWrite rejects mutating tools on a read-only profile.
func (e *Engine) AuthorizeWrite(p *config.Profile) error {
	if p.ReadOnly {
		return fmt.Errorf("profile %q is read-only", p.Name)
	}
	return nil
}

// ApprovalRequired applies the configured human-approval mode after policy
// authorization. It never weakens built-in or configured denials.
func (e *Engine) ApprovalRequired(cfg *config.Config, p *config.Profile, action, subject string, forced bool) (bool, string) {
	mode := cfg.ApprovalMode(p)
	if forced {
		return true, "command template requires approval"
	}
	if mode == "never" {
		return false, ""
	}
	if mode == "always" {
		return true, "profile requires approval for mutating actions"
	}
	switch action {
	case "command", "template", "background-command":
		for _, pattern := range riskyCommandPatterns {
			if pattern.re.MatchString(subject) {
				return true, pattern.reason
			}
		}
	case "file-write", "file-patch":
		return true, "overwrites a remote file"
	case "file-mkdir":
		return true, "creates a remote directory"
	case "file-rename":
		return true, "renames or replaces a remote path"
	case "file-remove":
		return true, "removes a remote path"
	}
	return false, ""
}

func isReadOnlyCommand(command string) bool {
	if strings.ContainsAny(command, "\r\n;&|><`") || strings.Contains(command, "$(") || strings.Contains(command, "${") {
		return false
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	binary := path.Base(strings.ReplaceAll(fields[0], `\`, "/"))
	if binary == "rg" {
		for _, field := range fields[1:] {
			if field == "--pre" || strings.HasPrefix(field, "--pre=") || field == "--pre-glob" || strings.HasPrefix(field, "--pre-glob=") {
				return false
			}
		}
	}
	if readOnlyCommands[binary] {
		return true
	}
	subcommands, ok := readOnlySubcommands[binary]
	if !ok || len(fields) < 2 {
		return false
	}
	for _, field := range fields[1:] {
		if strings.HasPrefix(field, "-") {
			continue
		}
		return subcommands[field]
	}
	return false
}

func catastrophicRemove(command string) bool {
	fields := strings.Fields(strings.ToLower(command))
	for i := range fields {
		binary := path.Base(strings.ReplaceAll(strings.Trim(fields[i], "'\""), `\`, "/"))
		if binary != "rm" {
			continue
		}
		recursive, force, root := false, false, false
		for _, field := range fields[i+1:] {
			field = strings.Trim(field, "'\"")
			if field == ";" || field == "&&" || field == "||" || field == "|" {
				break
			}
			switch field {
			case "--recursive":
				recursive = true
			case "--force":
				force = true
			default:
				if strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--") {
					flags := strings.TrimPrefix(field, "-")
					recursive = recursive || strings.Contains(flags, "r")
					force = force || strings.Contains(flags, "f")
				}
				root = root || strings.Trim(field, "/.*") == ""
			}
		}
		if recursive && force && root {
			return true
		}
	}
	return false
}
