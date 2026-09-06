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
		if hunk.oldCount == 0 {
			// A zero-length range starts after oldStart lines. This matters for
			// insertions in the middle of a file (for example, -1,0 inserts
			// between the first and second lines).
			start = hunk.oldStart
		}
		if start < cursor || start > len(oldLines) {
			return "", fmt.Errorf("patch hunk starts outside the current file at old line %d", hunk.oldStart)
		}
		output = append(output, oldLines[cursor:start]...)
		cursor = start
		newStart := hunk.newStart - 1
		if hunk.newCount == 0 {
			newStart = hunk.newStart
		}
		if newStart != len(output) {
			expected := len(output) + 1
			if hunk.newCount == 0 {
				expected = len(output)
			}
			return "", fmt.Errorf("patch hunk has inconsistent new start at line %d; expected %d", hunk.newStart, expected)
		}
		oldSeen, newSeen := 0, 0
		var previousPrefix byte
		newNoFinalNewline := false
		for _, line := range hunk.lines {
			if line == `\ No newline at end of file` {
				if previousPrefix == '+' || previousPrefix == ' ' {
					newNoFinalNewline = true
				}
				continue
			}
			if line == "" {
				return "", fmt.Errorf("invalid empty patch line in hunk")
			}
			content := line[1:]
			previousPrefix = line[0]
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
		if start+hunk.oldCount == len(oldLines) {
			// A hunk reaching the old EOF defines the new EOF. Normal unified
			// diff lines carry a newline; the explicit marker removes it.
			hadFinalNewline = len(output) > 0 && !newNoFinalNewline
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
			if len(hunks) > 0 && line != "" {
				return nil, fmt.Errorf("patch must describe exactly one file")
			}
			i++
			continue
		}
		match := hunkHeader.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("expected unified diff hunk header at patch line %d", i+1)
		}
		oldStart, err := patchNumber(match[1], 0)
		if err != nil {
			return nil, fmt.Errorf("invalid old start at patch line %d: %w", i+1, err)
		}
		oldCount, err := patchNumber(match[2], 1)
		if err != nil {
			return nil, fmt.Errorf("invalid old count at patch line %d: %w", i+1, err)
		}
		newStart, err := patchNumber(match[3], 0)
		if err != nil {
			return nil, fmt.Errorf("invalid new start at patch line %d: %w", i+1, err)
		}
		newCount, err := patchNumber(match[4], 1)
		if err != nil {
			return nil, fmt.Errorf("invalid new count at patch line %d: %w", i+1, err)
		}
		hunk := patchHunk{oldStart: oldStart, oldCount: oldCount, newStart: newStart, newCount: newCount}
		i++
		oldSeen, newSeen := 0, 0
		for oldSeen < hunk.oldCount || newSeen < hunk.newCount {
			if i >= len(lines) {
				return nil, fmt.Errorf("patch hunk at line %d is incomplete", i)
			}
			bodyLine := lines[i]
			if bodyLine == "" {
				return nil, fmt.Errorf("invalid empty patch line in hunk at patch line %d", i+1)
			}
			switch bodyLine[0] {
			case ' ':
				oldSeen++
				newSeen++
			case '-':
				oldSeen++
			case '+':
				newSeen++
			default:
				return nil, fmt.Errorf("invalid patch line prefix %q at patch line %d", bodyLine[0], i+1)
			}
			if oldSeen > hunk.oldCount || newSeen > hunk.newCount {
				return nil, fmt.Errorf("patch hunk count exceeds its header at patch line %d", i+1)
			}
			hunk.lines = append(hunk.lines, bodyLine)
			i++
			if i < len(lines) && lines[i] == `\ No newline at end of file` {
				hunk.lines = append(hunk.lines, lines[i])
				i++
			}
		}
		hunks = append(hunks, hunk)
	}
	if len(hunks) == 0 {
		return nil, fmt.Errorf("patch contains no hunks")
	}
	return hunks, nil
}

func patchNumber(value string, fallback int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return n, nil
}
