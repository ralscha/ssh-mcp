package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/audit"
	"ssh-mcp/internal/remote"
)

func (s *Service) registerFileTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-list", Description: "List a bounded number of entries in a remote directory.", Annotations: annotations(true, false)}, s.listDirectory)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-stat", Description: "Read portable metadata for a remote path without following its final symlink.", Annotations: annotations(true, false)}, s.statPath)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-read", Description: "Read a bounded byte range from a remote file as UTF-8 or base64.", Annotations: annotations(true, false)}, s.readFileRange)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-checksum", Description: "Compute the SHA-256 checksum of a size-limited remote file.", Annotations: annotations(true, false)}, s.checksumFile)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-write", Description: "Atomically replace a remote file with UTF-8 or base64 content.", Annotations: annotations(false, true)}, s.upload)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-apply-patch", Description: "Apply a unified diff to a UTF-8 remote file using an expected SHA-256 precondition and atomic replacement.", Annotations: annotations(false, true)}, s.applyPatch)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-mkdir", Description: "Create a remote directory with explicit permissions, optionally including missing parents.", Annotations: annotations(false, false)}, s.makeDirectory)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-rename", Description: "Rename a remote path, optionally atomically replacing an existing destination.", Annotations: annotations(false, true)}, s.renamePath)
	mcp.AddTool(server, &mcp.Tool{Name: "sftp-remove", Description: "Remove one remote file, symlink, or empty directory. Recursive deletion is intentionally unsupported.", Annotations: annotations(false, true)}, s.removePath)
}

type pathInput struct {
	RemotePath string `json:"remotePath"`
	Profile    string `json:"profile,omitempty"`
}

type listDirectoryInput struct {
	RemotePath string `json:"remotePath"`
	Profile    string `json:"profile,omitempty"`
	MaxEntries int    `json:"maxEntries,omitempty"`
}

type listDirectoryOutput struct {
	Profile string            `json:"profile"`
	Path    string            `json:"path"`
	Entries []remote.FileInfo `json:"entries"`
}

func (s *Service) listDirectory(ctx context.Context, _ *mcp.CallToolRequest, input listDirectoryInput) (*mcp.CallToolResult, listDirectoryOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, listDirectoryOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, listDirectoryOutput{}, err
	}
	if input.MaxEntries < 0 || input.MaxEntries > 10_000 {
		return nil, listDirectoryOutput{}, fmt.Errorf("maxEntries must be between 1 and 10000 when specified")
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	entries, err := s.backend.ListDirectory(ctx, profile, input.RemotePath, input.MaxEntries)
	if err != nil {
		_ = s.record(audit.Event{Action: "sftp-list", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "failed", Error: err.Error()})
		return nil, listDirectoryOutput{}, err
	}
	_ = s.record(audit.Event{Action: "sftp-list", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "completed"})
	return nil, listDirectoryOutput{Profile: profile.Name, Path: input.RemotePath, Entries: entries}, nil
}

type statOutput struct {
	Profile string          `json:"profile"`
	File    remote.FileInfo `json:"file"`
}

func (s *Service) statPath(ctx context.Context, _ *mcp.CallToolRequest, input pathInput) (*mcp.CallToolResult, statOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, statOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, statOutput{}, err
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	info, err := s.backend.Stat(ctx, profile, input.RemotePath)
	if err != nil {
		return nil, statOutput{}, err
	}
	return nil, statOutput{Profile: profile.Name, File: info}, nil
}

type readRangeInput struct {
	RemotePath string `json:"remotePath"`
	Profile    string `json:"profile,omitempty"`
	Offset     int64  `json:"offset,omitempty"`
	Length     int64  `json:"length,omitempty"`
	Encoding   string `json:"encoding,omitempty"`
}

type readRangeOutput struct {
	Profile    string `json:"profile"`
	RemotePath string `json:"remotePath"`
	Offset     int64  `json:"offset"`
	Bytes      int64  `json:"bytes"`
	Encoding   string `json:"encoding"`
	Content    string `json:"content"`
}

func (s *Service) readFileRange(ctx context.Context, _ *mcp.CallToolRequest, input readRangeInput) (*mcp.CallToolResult, readRangeOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, readRangeOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, readRangeOutput{}, err
	}
	limit := s.cfg.TransferLimit(profile)
	if input.Length == 0 {
		input.Length = limit
	}
	if input.Length < 0 || input.Length > limit {
		return nil, readRangeOutput{}, fmt.Errorf("length must be positive and no greater than the profile transfer limit of %d", limit)
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	data, err := s.backend.ReadRange(ctx, profile, input.RemotePath, input.Offset, input.Length)
	if err != nil {
		_ = s.record(audit.Event{Action: "sftp-read", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, readRangeOutput{}, err
	}
	encoding, content, err := encodeContent(data, input.Encoding)
	if err != nil {
		return nil, readRangeOutput{}, err
	}
	output := readRangeOutput{Profile: profile.Name, RemotePath: input.RemotePath, Offset: input.Offset, Bytes: int64(len(data)), Encoding: encoding, Content: content}
	_ = s.record(audit.Event{Action: "sftp-read", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "completed", DurationMS: time.Since(started).Milliseconds(), Bytes: int64(len(data))})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: content}}}, output, nil
}

func encodeContent(data []byte, encoding string) (string, string, error) {
	switch strings.ToLower(encoding) {
	case "", "utf8", "utf-8", "text":
		if !utf8.Valid(data) {
			return "", "", fmt.Errorf("remote bytes are not valid UTF-8; retry with encoding=base64")
		}
		return "utf8", string(data), nil
	case "base64":
		return "base64", base64.StdEncoding.EncodeToString(data), nil
	default:
		return "", "", fmt.Errorf("encoding must be utf8 or base64")
	}
}

type checksumOutput struct {
	Profile    string `json:"profile"`
	RemotePath string `json:"remotePath"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
}

func (s *Service) checksumFile(ctx context.Context, _ *mcp.CallToolRequest, input pathInput) (*mcp.CallToolResult, checksumOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, checksumOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, checksumOutput{}, err
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	checksum, bytes, err := s.backend.Checksum(ctx, profile, input.RemotePath, s.cfg.TransferLimit(profile))
	if err != nil {
		_ = s.record(audit.Event{Action: "sftp-checksum", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, checksumOutput{}, err
	}
	_ = s.record(audit.Event{Action: "sftp-checksum", Profile: profile.Name, Target: input.RemotePath, Decision: "allowed", Outcome: "completed", DurationMS: time.Since(started).Milliseconds(), Bytes: bytes})
	output := checksumOutput{Profile: profile.Name, RemotePath: input.RemotePath, SHA256: checksum, Bytes: bytes}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: checksum}}}, output, nil
}

type applyPatchInput struct {
	RemotePath     string `json:"remotePath"`
	Patch          string `json:"patch" jsonschema:"unified diff with one or more hunks"`
	ExpectedSHA256 string `json:"expectedSha256" jsonschema:"lowercase hexadecimal SHA-256 of the current remote file"`
	Profile        string `json:"profile,omitempty"`
}

type applyPatchOutput struct {
	Profile        string `json:"profile"`
	RemotePath     string `json:"remotePath"`
	PreviousSHA256 string `json:"previousSha256"`
	SHA256         string `json:"sha256"`
	Bytes          int64  `json:"bytes"`
}

func (s *Service) applyPatch(ctx context.Context, req *mcp.CallToolRequest, input applyPatchInput) (*mcp.CallToolResult, applyPatchOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, applyPatchOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, applyPatchOutput{}, err
	}
	if err := s.policy.AuthorizeWrite(profile); err != nil {
		return nil, applyPatchOutput{}, fmt.Errorf("policy denied sftp-apply-patch: %w", err)
	}
	if input.ExpectedSHA256 == "" {
		return nil, applyPatchOutput{}, fmt.Errorf("expectedSha256 is required; call sftp-checksum first")
	}
	if int64(len(input.Patch)) > s.cfg.TransferLimit(profile) {
		return nil, applyPatchOutput{}, fmt.Errorf("patch exceeds profile transfer limit")
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	info, err := s.backend.Stat(ctx, profile, input.RemotePath)
	if err != nil {
		return nil, applyPatchOutput{}, err
	}
	if !info.IsRegular {
		return nil, applyPatchOutput{}, fmt.Errorf("patch target must be a regular file")
	}
	data, err := s.backend.Download(ctx, profile, input.RemotePath, s.cfg.TransferLimit(profile))
	if err != nil {
		return nil, applyPatchOutput{}, err
	}
	if !utf8.Valid(data) {
		return nil, applyPatchOutput{}, fmt.Errorf("patch target is not valid UTF-8")
	}
	before := sha256.Sum256(data)
	beforeHex := hex.EncodeToString(before[:])
	want := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(input.ExpectedSHA256)), "sha256:")
	if beforeHex != want {
		return nil, applyPatchOutput{}, fmt.Errorf("remote file changed: expected SHA-256 %s, received %s", want, beforeHex)
	}
	patched, err := applyUnifiedPatch(string(data), input.Patch)
	if err != nil {
		return nil, applyPatchOutput{}, err
	}
	if int64(len(patched)) > s.cfg.TransferLimit(profile) {
		return nil, applyPatchOutput{}, fmt.Errorf("patched file exceeds profile transfer limit")
	}
	decision, pending, err := s.requireApproval(ctx, req, profile, "file-patch", input.RemotePath, patchApprovalBinding(input.RemotePath, want, input.Patch), false)
	if err != nil {
		return nil, applyPatchOutput{}, err
	}
	if pending != nil {
		return pending, applyPatchOutput{}, nil
	}
	current, _, err := s.backend.Checksum(ctx, profile, input.RemotePath, s.cfg.TransferLimit(profile))
	if err != nil {
		return nil, applyPatchOutput{}, fmt.Errorf("recheck remote file before patch: %w", err)
	}
	if current != beforeHex {
		return nil, applyPatchOutput{}, fmt.Errorf("remote file changed while approval was pending: expected SHA-256 %s, received %s", beforeHex, current)
	}
	started := time.Now()
	n, err := s.backend.Upload(ctx, profile, input.RemotePath, []byte(patched), os.FileMode(info.ModeBits))
	if err != nil {
		_ = s.record(audit.Event{Action: "sftp-apply-patch", Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Bytes: n, Error: err.Error()})
		return nil, applyPatchOutput{}, err
	}
	after := sha256.Sum256([]byte(patched))
	afterHex := hex.EncodeToString(after[:])
	if err := s.record(audit.Event{Action: "sftp-apply-patch", Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "completed", DurationMS: time.Since(started).Milliseconds(), Bytes: n}); err != nil {
		return nil, applyPatchOutput{}, fmt.Errorf("patch completed but audit logging failed: %w", err)
	}
	output := applyPatchOutput{Profile: profile.Name, RemotePath: input.RemotePath, PreviousSHA256: beforeHex, SHA256: afterHex, Bytes: n}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Patched %s atomically; SHA-256 %s", input.RemotePath, afterHex)}}}, output, nil
}

type mkdirInput struct {
	RemotePath string `json:"remotePath"`
	Profile    string `json:"profile,omitempty"`
	Mode       int    `json:"mode,omitempty" jsonschema:"optional Unix permission bits as a decimal integer; defaults to 0700"`
	Parents    bool   `json:"parents,omitempty" jsonschema:"create missing parent directories"`
}

type pathMutationOutput struct {
	Profile string `json:"profile"`
	Path    string `json:"path"`
}

func (s *Service) makeDirectory(ctx context.Context, req *mcp.CallToolRequest, input mkdirInput) (*mcp.CallToolResult, pathMutationOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, pathMutationOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, pathMutationOutput{}, err
	}
	if err := s.policy.AuthorizeWrite(profile); err != nil {
		return nil, pathMutationOutput{}, fmt.Errorf("policy denied sftp-mkdir: %w", err)
	}
	if input.Mode < 0 || input.Mode > 0o777 {
		return nil, pathMutationOutput{}, fmt.Errorf("mode must be between 0 and 0777")
	}
	mode := os.FileMode(input.Mode)
	if mode == 0 {
		mode = 0o700
	}
	binding := fmt.Sprintf("path=%q\nmode=%04o\nparents=%t", input.RemotePath, mode.Perm(), input.Parents)
	decision, pending, err := s.requireApproval(ctx, req, profile, "file-mkdir", input.RemotePath, binding, false)
	if err != nil {
		return nil, pathMutationOutput{}, err
	}
	if pending != nil {
		return pending, pathMutationOutput{}, nil
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	if err := s.backend.Mkdir(ctx, profile, input.RemotePath, mode, input.Parents); err != nil {
		_ = s.record(audit.Event{Action: "sftp-mkdir", Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, pathMutationOutput{}, err
	}
	if err := s.record(audit.Event{Action: "sftp-mkdir", Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "completed", DurationMS: time.Since(started).Milliseconds()}); err != nil {
		return nil, pathMutationOutput{}, fmt.Errorf("directory created but audit logging failed: %w", err)
	}
	output := pathMutationOutput{Profile: profile.Name, Path: input.RemotePath}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Created directory %s on %s", input.RemotePath, profile.Name)}}}, output, nil
}

type renameInput struct {
	OldPath   string `json:"oldPath"`
	NewPath   string `json:"newPath"`
	Profile   string `json:"profile,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"atomically replace an existing destination; requires POSIX rename support"`
}

type renameOutput struct {
	Profile string `json:"profile"`
	OldPath string `json:"oldPath"`
	NewPath string `json:"newPath"`
}

func (s *Service) renamePath(ctx context.Context, req *mcp.CallToolRequest, input renameInput) (*mcp.CallToolResult, renameOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, renameOutput{}, err
	}
	if err := validateToolPath(input.OldPath); err != nil {
		return nil, renameOutput{}, fmt.Errorf("oldPath: %w", err)
	}
	if err := validateToolPath(input.NewPath); err != nil {
		return nil, renameOutput{}, fmt.Errorf("newPath: %w", err)
	}
	if input.OldPath == input.NewPath {
		return nil, renameOutput{}, fmt.Errorf("oldPath and newPath must differ")
	}
	if err := s.policy.AuthorizeWrite(profile); err != nil {
		return nil, renameOutput{}, fmt.Errorf("policy denied sftp-rename: %w", err)
	}
	subject := input.OldPath + " -> " + input.NewPath
	binding := fmt.Sprintf("old-path=%q\nnew-path=%q\noverwrite=%t", input.OldPath, input.NewPath, input.Overwrite)
	decision, pending, err := s.requireApproval(ctx, req, profile, "file-rename", subject, binding, false)
	if err != nil {
		return nil, renameOutput{}, err
	}
	if pending != nil {
		return pending, renameOutput{}, nil
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	if err := s.backend.Rename(ctx, profile, input.OldPath, input.NewPath, input.Overwrite); err != nil {
		_ = s.record(audit.Event{Action: "sftp-rename", Profile: profile.Name, Target: subject, Decision: decision, Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, renameOutput{}, err
	}
	if err := s.record(audit.Event{Action: "sftp-rename", Profile: profile.Name, Target: subject, Decision: decision, Outcome: "completed", DurationMS: time.Since(started).Milliseconds()}); err != nil {
		return nil, renameOutput{}, fmt.Errorf("path renamed but audit logging failed: %w", err)
	}
	output := renameOutput{Profile: profile.Name, OldPath: input.OldPath, NewPath: input.NewPath}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Renamed %s to %s on %s", input.OldPath, input.NewPath, profile.Name)}}}, output, nil
}

type removeOutput struct {
	Profile string          `json:"profile"`
	Path    string          `json:"path"`
	Removed remote.FileInfo `json:"removed"`
}

func (s *Service) removePath(ctx context.Context, req *mcp.CallToolRequest, input pathInput) (*mcp.CallToolResult, removeOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, removeOutput{}, err
	}
	if err := validateToolPath(input.RemotePath); err != nil {
		return nil, removeOutput{}, err
	}
	if err := s.policy.AuthorizeWrite(profile); err != nil {
		return nil, removeOutput{}, fmt.Errorf("policy denied sftp-remove: %w", err)
	}
	decision, pending, err := s.requireApproval(ctx, req, profile, "file-remove", input.RemotePath, fmt.Sprintf("path=%q", input.RemotePath), false)
	if err != nil {
		return nil, removeOutput{}, err
	}
	if pending != nil {
		return pending, removeOutput{}, nil
	}
	ctx, cancel := s.transferContext(ctx, profile)
	defer cancel()
	started := time.Now()
	removed, err := s.backend.Remove(ctx, profile, input.RemotePath)
	if err != nil {
		_ = s.record(audit.Event{Action: "sftp-remove", Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "failed", DurationMS: time.Since(started).Milliseconds(), Error: err.Error()})
		return nil, removeOutput{}, err
	}
	if err := s.record(audit.Event{Action: "sftp-remove", Profile: profile.Name, Target: input.RemotePath, Decision: decision, Outcome: "completed", DurationMS: time.Since(started).Milliseconds()}); err != nil {
		return nil, removeOutput{}, fmt.Errorf("path removed but audit logging failed: %w", err)
	}
	output := removeOutput{Profile: profile.Name, Path: input.RemotePath, Removed: removed}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Removed %s on %s", input.RemotePath, profile.Name)}}}, output, nil
}

func validateToolPath(remotePath string) error {
	if remotePath == "" || strings.IndexByte(remotePath, 0) >= 0 {
		return fmt.Errorf("remote path must be non-empty and contain no NUL byte")
	}
	return nil
}
