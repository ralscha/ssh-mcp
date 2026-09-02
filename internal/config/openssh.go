package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

type sshDirective struct {
	patterns []string
	key      string
	value    string
}

type sshConfig struct {
	directives []sshDirective
}

func (c *Config) applyOpenSSHConfig() error {
	requested := len(c.Defaults.ImportSSHHosts) > 0
	for i := range c.Profiles {
		requested = requested || c.Profiles[i].SSHConfigHost != ""
	}
	if !requested {
		return nil
	}
	parsed, err := parseSSHConfig(c.Defaults.SSHConfigFile)
	if err != nil {
		return fmt.Errorf("load OpenSSH config: %w", err)
	}
	existing := make(map[string]bool, len(c.Profiles))
	for i := range c.Profiles {
		existing[c.Profiles[i].Name] = true
	}
	for _, alias := range c.Defaults.ImportSSHHosts {
		if alias == "" || strings.ContainsAny(alias, "*?!") {
			return fmt.Errorf("defaults.importSSHHosts contains invalid exact host alias %q", alias)
		}
		if !existing[alias] {
			c.Profiles = append(c.Profiles, Profile{Name: alias, SSHConfigHost: alias})
			existing[alias] = true
		}
	}
	for i := 0; i < len(c.Profiles); i++ {
		p := &c.Profiles[i]
		if p.SSHConfigHost != "" {
			if err := parsed.apply(p, p.SSHConfigHost); err != nil {
				return fmt.Errorf("profile %q: %w", p.Name, err)
			}
		}
		if p.ProxyJump == "none" {
			p.ProxyJump = ""
		}
		if p.ProxyJump != "" && !existing[p.ProxyJump] {
			jump, err := parsed.jumpProfile(p.ProxyJump)
			if err != nil {
				return fmt.Errorf("profile %q proxyJump: %w", p.Name, err)
			}
			c.Profiles = append(c.Profiles, jump)
			existing[jump.Name] = true
		}
	}
	return nil
}

func parseSSHConfig(filename string) (*sshConfig, error) {
	if filename == "" {
		return nil, errors.New("defaults.sshConfigFile is empty")
	}
	var directives []sshDirective
	seen := make(map[string]bool)
	if err := parseSSHFile(filename, []string{"*"}, seen, &directives); err != nil {
		return nil, err
	}
	return &sshConfig{directives: directives}, nil
}

func parseSSHFile(filename string, current []string, seen map[string]bool, out *[]sshDirective) error {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	if seen[abs] {
		return fmt.Errorf("include cycle involving %q", abs)
	}
	seen[abs] = true
	defer delete(seen, abs)
	f, err := os.Open(abs) //nolint:gosec // abs is an administrator-selected OpenSSH config or Include
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	lineNumber := 0
	patterns := append([]string(nil), current...)
	for scanner.Scan() {
		lineNumber++
		fields, err := sshFields(scanner.Text())
		if err != nil {
			return fmt.Errorf("%s:%d: %w", abs, lineNumber, err)
		}
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(fields[0], "="))
		values := fields[1:]
		if len(values) > 0 && values[0] == "=" {
			values = values[1:]
		}
		if len(values) == 0 {
			continue
		}
		switch key {
		case "host":
			patterns = append([]string(nil), values...)
		case "match":
			patterns = []string{"!__ssh_mcp_never_match__"}
		case "include":
			for _, include := range values {
				include, err = ExpandPath(include)
				if err != nil {
					return err
				}
				if !filepath.IsAbs(include) {
					include = filepath.Join(filepath.Dir(abs), include)
				}
				matches, err := filepath.Glob(include)
				if err != nil {
					return fmt.Errorf("invalid Include pattern %q: %w", include, err)
				}
				for _, match := range matches {
					if err := parseSSHFile(match, patterns, seen, out); err != nil {
						return err
					}
				}
			}
		default:
			*out = append(*out, sshDirective{patterns: append([]string(nil), patterns...), key: key, value: strings.Join(values, " ")})
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %q: %w", abs, err)
	}
	return nil
}

func sshFields(line string) ([]string, error) {
	var fields []string
	var b strings.Builder
	var quote rune
	flush := func() {
		if b.Len() > 0 {
			fields = append(fields, b.String())
			b.Reset()
		}
	}
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\\' {
			// OpenSSH permits backslash escaping, but an unquoted Windows path
			// also uses backslashes. Only consume the slash for characters that
			// need escaping; preserve it before ordinary path characters.
			if i+1 < len(runes) {
				next := runes[i+1]
				if next == '\\' || next == '\'' || next == '"' || next == '#' || next == ' ' || next == '\t' {
					b.WriteRune(next)
					i++
					continue
				}
			}
			b.WriteRune(r)
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			break
		}
		if r == '=' && len(fields) == 0 {
			flush()
			fields = append(fields, "=")
			continue
		}
		if r == ' ' || r == '\t' {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return fields, nil
}

func (c *sshConfig) apply(p *Profile, alias string) error {
	values := make(map[string]string)
	for _, d := range c.directives {
		if hostPatternsMatch(d.patterns, alias) {
			if _, set := values[d.key]; !set {
				values[d.key] = d.value
			}
		}
	}
	if p.Host == "" {
		p.Host = values["hostname"]
		if p.Host == "" {
			p.Host = alias
		}
	}
	if p.User == "" {
		p.User = values["user"]
		if p.User == "" {
			p.User = currentUsername()
		}
	}
	if p.Port == 0 && values["port"] != "" {
		port, err := strconv.Atoi(values["port"])
		if err != nil {
			return fmt.Errorf("invalid OpenSSH Port %q", values["port"])
		}
		p.Port = port
	}
	if p.KeyRef == "" && values["identityfile"] != "" {
		p.KeyRef = expandSSHTokens(values["identityfile"], alias, p)
		if p.Auth == "" {
			p.Auth = "key"
		}
	}
	if p.ProxyJump == "" {
		p.ProxyJump = strings.TrimSpace(values["proxyjump"])
	}
	p.Host = expandSSHTokens(p.Host, alias, p)
	return nil
}

func (c *sshConfig) jumpProfile(target string) (Profile, error) {
	if strings.Contains(target, ",") {
		return Profile{}, errors.New("multiple ProxyJump hops are not supported; chain configured profiles instead")
	}
	alias := target
	p := Profile{Name: target, SSHConfigHost: target, JumpOnly: true}
	if err := c.apply(&p, alias); err != nil {
		return Profile{}, err
	}
	// A literal [user@]host[:port] is valid even when it has no Host block.
	literal := target
	if at := strings.LastIndex(literal, "@"); at >= 0 {
		p.User = literal[:at]
		literal = literal[at+1:]
	}
	if host, port, err := net.SplitHostPort(literal); err == nil {
		p.Host = host
		parsedPort, _ := strconv.Atoi(port)
		p.Port = parsedPort
	} else if literal != target {
		p.Host = literal
	}
	return p, nil
}

func hostPatternsMatch(patterns []string, host string) bool {
	matched := false
	host = strings.ToLower(host)
	for _, pattern := range patterns {
		negated := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(strings.ToLower(pattern), "!")
		ok, _ := path.Match(pattern, host)
		if ok && negated {
			return false
		}
		matched = matched || ok
	}
	return matched
}

func currentUsername() string {
	if current, err := user.Current(); err == nil && current.Username != "" {
		name := current.Username
		if slash := strings.LastIndexAny(name, `\\/`); slash >= 0 {
			name = name[slash+1:]
		}
		return name
	}
	return os.Getenv("USERNAME")
}

func expandSSHTokens(value, alias string, p *Profile) string {
	port := p.Port
	if port == 0 {
		port = 22
	}
	value = strings.ReplaceAll(value, "%n", alias)
	value = strings.ReplaceAll(value, "%h", p.Host)
	value = strings.ReplaceAll(value, "%r", p.User)
	value = strings.ReplaceAll(value, "%p", strconv.Itoa(port))
	return value
}

func (c *Config) validateProxyJumpCycles() error {
	profiles := make(map[string]*Profile, len(c.Profiles))
	for i := range c.Profiles {
		profiles[c.Profiles[i].Name] = &c.Profiles[i]
	}
	for i := range c.Profiles {
		seen := map[string]bool{}
		for p := &c.Profiles[i]; p.ProxyJump != ""; p = profiles[p.ProxyJump] {
			if seen[p.Name] {
				return fmt.Errorf("proxyJump cycle involving profile %q", p.Name)
			}
			seen[p.Name] = true
		}
	}
	return nil
}
