package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

type patchHunk struct {
	oldStart, oldCount int
	newStart, newCount int
	lines              []string
}

func applyUnifiedPatch(original, patch string) (string, error) {
	hunks, err := parsePatch(patch)
	if err != nil {
		return "", err
	}
	newline := "\n"
	if strings.Contains(original, "\r\n") {
		newline = "\r\n"
	}
	hadFinalNewline := strings.HasSuffix(original, "\n")
	original = strings.ReplaceAll(original, "\r\n", "\n")
	oldLines := strings.Split(strings.TrimSuffix(original, "\n"), "\n")
	if original == "" {
		oldLines = nil
	}
	var output []string
	cursor := 0
	for _, hunk := range hunks {
		start := hunk.oldStart - 1
		if hunk.oldStart == 0 {
			start = 0
		}
		if start < cursor || start > len(oldLines) {
			return "", fmt.Errorf("patch hunk starts outside the current file at old line %d", hunk.oldStart)
		}
		output = append(output, oldLines[cursor:start]...)
		cursor = start
		oldSeen, newSeen := 0, 0
		for _, line := range hunk.lines {
			if line == `\ No newline at end of file` {
				hadFinalNewline = false
				continue
			}
			if line == "" {
				return "", fmt.Errorf("invalid empty patch line in hunk")
			}
			content := line[1:]
			switch line[0] {
			case ' ':
				if cursor >= len(oldLines) || oldLines[cursor] != content {
					return "", fmt.Errorf("patch context mismatch at old line %d", cursor+1)
				}
				output = append(output, content)
				cursor++
				oldSeen++
				newSeen++
			case '-':
				if cursor >= len(oldLines) || oldLines[cursor] != content {
					return "", fmt.Errorf("patch deletion mismatch at old line %d", cursor+1)
				}
				cursor++
				oldSeen++
			case '+':
				output = append(output, content)
				newSeen++
			default:
				return "", fmt.Errorf("invalid patch line prefix %q", line[0])
			}
		}
		if oldSeen != hunk.oldCount || newSeen != hunk.newCount {
			return "", fmt.Errorf("patch hunk count mismatch: header says -%d +%d, body has -%d +%d", hunk.oldCount, hunk.newCount, oldSeen, newSeen)
		}
	}
	output = append(output, oldLines[cursor:]...)
	result := strings.Join(output, newline)
	if hadFinalNewline && len(output) > 0 {
		result += newline
	}
	return result, nil
}

func parsePatch(patch string) ([]patchHunk, error) {
	patch = strings.ReplaceAll(patch, "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(patch, "\n"), "\n")
	var hunks []patchHunk
	for i := 0; i < len(lines); {
		line := lines[i]
		if strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "diff ") || strings.HasPrefix(line, "index ") || line == "" {
			i++
			continue
		}
		match := hunkHeader.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("expected unified diff hunk header at patch line %d", i+1)
		}
		hunk := patchHunk{oldStart: atoi(match[1]), oldCount: count(match[2]), newStart: atoi(match[3]), newCount: count(match[4])}
		i++
		for i < len(lines) && !strings.HasPrefix(lines[i], "@@ ") {
			if strings.HasPrefix(lines[i], "--- ") || strings.HasPrefix(lines[i], "+++ ") {
				break
			}
			hunk.lines = append(hunk.lines, lines[i])
			i++
		}
		hunks = append(hunks, hunk)
	}
	if len(hunks) == 0 {
		return nil, fmt.Errorf("patch contains no hunks")
	}
	return hunks, nil
}

func atoi(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func count(value string) int {
	if value == "" {
		return 1
	}
	return atoi(value)
}
