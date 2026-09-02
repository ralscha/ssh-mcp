package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	templateNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	placeholderPattern  = regexp.MustCompile(`\{\{([A-Za-z][A-Za-z0-9_-]*)\}\}`)
)

func validateTemplates(p *Profile) error {
	names := make(map[string]bool, len(p.CommandTemplates))
	for i := range p.CommandTemplates {
		t := &p.CommandTemplates[i]
		if !templateNamePattern.MatchString(t.Name) {
			return fmt.Errorf("profile %q commandTemplates[%d]: name must contain lowercase letters, digits, and hyphens", p.Name, i)
		}
		if names[t.Name] {
			return fmt.Errorf("profile %q: duplicate command template %q", p.Name, t.Name)
		}
		names[t.Name] = true
		if strings.TrimSpace(t.Command) == "" || strings.IndexByte(t.Command, 0) >= 0 {
			return fmt.Errorf("profile %q command template %q: command must be non-empty and contain no NUL byte", p.Name, t.Name)
		}
		declared := make(map[string]bool, len(t.Parameters))
		for _, name := range t.Parameters {
			if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`).MatchString(name) {
				return fmt.Errorf("profile %q command template %q: invalid parameter %q", p.Name, t.Name, name)
			}
			if declared[name] {
				return fmt.Errorf("profile %q command template %q: duplicate parameter %q", p.Name, t.Name, name)
			}
			declared[name] = true
		}
		used := make(map[string]bool)
		for _, match := range placeholderPattern.FindAllStringSubmatch(t.Command, -1) {
			used[match[1]] = true
			if !declared[match[1]] {
				return fmt.Errorf("profile %q command template %q: placeholder %q is not declared", p.Name, t.Name, match[1])
			}
		}
		for _, name := range t.Parameters {
			if !used[name] {
				return fmt.Errorf("profile %q command template %q: parameter %q is unused", p.Name, t.Name, name)
			}
		}
	}
	return nil
}

// Template returns a named command template from a profile.
func (p *Profile) Template(name string) (*CommandTemplate, error) {
	for i := range p.CommandTemplates {
		if p.CommandTemplates[i].Name == name {
			return &p.CommandTemplates[i], nil
		}
	}
	return nil, fmt.Errorf("profile %q has no command template %q", p.Name, name)
}

// Render expands a template using POSIX-shell quoting for every argument.
func (t *CommandTemplate) Render(arguments map[string]string) (string, error) {
	allowed := make(map[string]bool, len(t.Parameters))
	for _, name := range t.Parameters {
		allowed[name] = true
		if _, ok := arguments[name]; !ok {
			return "", fmt.Errorf("missing template argument %q", name)
		}
	}
	var extra []string
	for name := range arguments {
		if !allowed[name] {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return "", fmt.Errorf("unknown template arguments: %s", strings.Join(extra, ", "))
	}
	command := placeholderPattern.ReplaceAllStringFunc(t.Command, func(placeholder string) string {
		name := placeholderPattern.FindStringSubmatch(placeholder)[1]
		return shellQuote(arguments[name])
	})
	return command, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
