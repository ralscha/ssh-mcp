package server

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/audit"
	"ssh-mcp/internal/config"
	"ssh-mcp/internal/jobs"
	"ssh-mcp/internal/remote"
)

const tasksExtension = "io.modelcontextprotocol/tasks"

func (s *Service) record(event audit.Event) error {
	return s.audit.Append(event)
}

func (s *Service) requireApproval(_ context.Context, req *mcp.CallToolRequest, profile *config.Profile, action, subject, binding string, forced bool) (string, *mcp.CallToolResult, error) {
	required, reason := s.policy.ApprovalRequired(s.cfg, profile, action, subject, forced)
	if !required {
		if err := s.record(audit.Event{Action: action, Profile: profile.Name, Command: commandSubject(action, subject), Target: targetSubject(action, subject), Decision: "allowed", Outcome: "authorized"}); err != nil {
			return "", nil, fmt.Errorf("audit authorization decision: %w", err)
		}
		return "allowed", nil, nil
	}
	if req == nil || req.Session == nil {
		return "", nil, fmt.Errorf("approval required because this action %s, but no MCP client session is available", reason)
	}
	message := fmt.Sprintf("Approve %s on SSH profile %q?\nReason: %s\nTarget: %q\nBound parameters:\n%s", action, profile.Name, reason, subject, binding)
	request := &mcp.ElicitParams{
		Mode:    "form",
		Message: message,
		RequestedSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"confirm"},
			"properties": map[string]any{
				"confirm": map[string]any{"type": "boolean", "title": "Confirm this operation"},
			},
		},
	}
	responseValue, hasResponse := req.Params.InputResponses["ssh-approval"]
	if !hasResponse {
		state, err := s.signApprovalState(action, profile.Name, binding)
		if err != nil {
			return "", nil, err
		}
		return "", &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{"ssh-approval": request},
			RequestState:  state,
		}, nil
	}
	if err := s.verifyApprovalState(req.Params.RequestState, action, profile.Name, binding); err != nil {
		_ = s.record(audit.Event{Action: action, Profile: profile.Name, Command: commandSubject(action, subject), Target: targetSubject(action, subject), Decision: "invalid-approval", Outcome: "not-run", Error: err.Error()})
		return "", nil, err
	}
	response, ok := responseValue.(*mcp.ElicitResult)
	if !ok {
		return "", nil, fmt.Errorf("approval response has unexpected type %T", responseValue)
	}
	confirmed, _ := response.Content["confirm"].(bool)
	if response.Action != "accept" || !confirmed {
		_ = s.record(audit.Event{Action: action, Profile: profile.Name, Command: commandSubject(action, subject), Target: targetSubject(action, subject), Decision: "declined", Outcome: "not-run"})
		return "", nil, fmt.Errorf("operation was not approved")
	}
	if err := s.record(audit.Event{Action: action, Profile: profile.Name, Command: commandSubject(action, subject), Target: targetSubject(action, subject), Decision: "approved", Outcome: "authorized"}); err != nil {
		return "", nil, fmt.Errorf("audit approval decision: %w", err)
	}
	return "approved", nil, nil
}

func (s *Service) signApprovalState(action, profile, subject string) (string, error) {
	subjectHash := sha256.Sum256([]byte(subject))
	nonce := make([]byte, 16)
	if _, err := cryptorand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate approval nonce: %w", err)
	}
	payload := approvalStatePayload{
		Expires: time.Now().Add(5 * time.Minute).Unix(), Action: action, Profile: profile,
		SubjectHash: hex.EncodeToString(subjectHash[:]), Nonce: hex.EncodeToString(nonce),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode approval state: %w", err)
	}
	mac := hmac.New(sha256.New, s.approvalKey)
	_, _ = mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(append(body, mac.Sum(nil)...)), nil
}

func (s *Service) verifyApprovalState(state, action, profile, subject string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(decoded) <= sha256.Size {
		return fmt.Errorf("invalid approval request state")
	}
	body, macBytes := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, s.approvalKey)
	_, _ = mac.Write(body)
	if !hmac.Equal(macBytes, mac.Sum(nil)) {
		return fmt.Errorf("approval request state signature is invalid")
	}
	var payload approvalStatePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("invalid approval request state")
	}
	if time.Now().Unix() > payload.Expires {
		return fmt.Errorf("approval request state has expired")
	}
	subjectHash := sha256.Sum256([]byte(subject))
	if payload.Action != action || payload.Profile != profile || payload.SubjectHash != hex.EncodeToString(subjectHash[:]) || payload.Nonce == "" {
		return fmt.Errorf("approval request does not match this operation")
	}
	stateHash := sha256.Sum256([]byte(state))
	stateID := hex.EncodeToString(stateHash[:])
	s.approvalMu.Lock()
	defer s.approvalMu.Unlock()
	now := time.Now()
	for id, expiry := range s.usedApprovals {
		if now.After(expiry) {
			delete(s.usedApprovals, id)
		}
	}
	if _, used := s.usedApprovals[stateID]; used {
		return fmt.Errorf("approval response was already used")
	}
	s.usedApprovals[stateID] = time.Unix(payload.Expires, 0)
	return nil
}

type approvalStatePayload struct {
	Expires     int64  `json:"expires"`
	Action      string `json:"action"`
	Profile     string `json:"profile"`
	SubjectHash string `json:"subjectHash"`
	Nonce       string `json:"nonce"`
}

func commandSubject(action, subject string) string {
	if action == "command" || action == "template" || action == "background-command" {
		return subject
	}
	return ""
}

func targetSubject(action, subject string) string {
	if strings.HasPrefix(action, "file-") {
		return subject
	}
	return ""
}

func commandApprovalBinding(command string, tty bool, stdin string) string {
	stdinHash := sha256.Sum256([]byte(stdin))
	return fmt.Sprintf("command=%q\ntty=%t\nstdin-bytes=%d\nstdin-sha256=%x", command, tty, len(stdin), stdinHash)
}

func uploadApprovalBinding(remotePath string, data []byte, mode os.FileMode) string {
	contentHash := sha256.Sum256(data)
	return fmt.Sprintf("path=%q\nmode=%04o\ncontent-bytes=%d\ncontent-sha256=%x", remotePath, mode.Perm(), len(data), contentHash)
}

func patchApprovalBinding(remotePath, expectedSHA256, patch string) string {
	patchHash := sha256.Sum256([]byte(patch))
	return fmt.Sprintf("path=%q\nexpected-sha256=%q\npatch-bytes=%d\npatch-sha256=%x", remotePath, expectedSHA256, len(patch), patchHash)
}

func (s *Service) registerCommandTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "list-command-templates", Description: "List the configured, narrowly scoped command templates for a profile.", Annotations: annotations(true, false)}, s.listCommandTemplates)
	mcp.AddTool(server, &mcp.Tool{Name: "run-command-template", Description: "Run a configured command template. Every argument is POSIX-shell quoted before substitution.", Annotations: annotations(false, true)}, s.runCommandTemplate)
	mcp.AddTool(server, &mcp.Tool{Name: "diagnose-connection", Description: "Diagnose DNS, SSH agent keys, host-key verification, proxy jump, and authentication without exposing secrets.", Annotations: annotations(true, false)}, s.diagnoseConnection)
	mcp.AddTool(server, &mcp.Tool{Name: "start-command", Description: "Start a policy-gated command as a durable background job. Tasks-capable clients receive an MCP Task; other clients receive a job ID.", Annotations: annotations(false, true)}, s.startCommand)
	mcp.AddTool(server, &mcp.Tool{Name: "job-status", Description: "Get the status and final result metadata of a background command job.", Annotations: annotations(true, false)}, s.jobStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "job-output", Description: "Get captured output for a completed or failed background command job.", Annotations: annotations(true, false)}, s.jobOutput)
	mcp.AddTool(server, &mcp.Tool{Name: "cancel-job", Description: "Cooperatively cancel a running background SSH command.", Annotations: annotations(false, true)}, s.cancelJob)
}

type profileInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
}

type commandTemplateInfo struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	Parameters       []string `json:"parameters"`
	ReadOnly         bool     `json:"readOnly"`
	RequiresApproval bool     `json:"requiresApproval"`
}

type listTemplatesOutput struct {
	Profile   string                `json:"profile"`
	Templates []commandTemplateInfo `json:"templates"`
}

func (s *Service) listCommandTemplates(_ context.Context, _ *mcp.CallToolRequest, input profileInput) (*mcp.CallToolResult, listTemplatesOutput, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, listTemplatesOutput{}, err
	}
	output := listTemplatesOutput{Profile: profile.Name, Templates: make([]commandTemplateInfo, 0, len(profile.CommandTemplates))}
	for _, template := range profile.CommandTemplates {
		output.Templates = append(output.Templates, commandTemplateInfo{Name: template.Name, Description: template.Description, Parameters: template.Parameters, ReadOnly: template.ReadOnly, RequiresApproval: template.RequiresApproval})
	}
	return nil, output, nil
}

type commandTemplateInput struct {
	Profile   string            `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
	Template  string            `json:"template" jsonschema:"configured template name"`
	Arguments map[string]string `json:"arguments,omitempty" jsonschema:"template arguments; every value is shell quoted"`
	TTY       bool              `json:"tty,omitempty"`
	Stdin     string            `json:"stdin,omitempty"`
}

func (s *Service) runCommandTemplate(ctx context.Context, req *mcp.CallToolRequest, input commandTemplateInput) (*mcp.CallToolResult, remote.CommandResult, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	template, err := profile.Template(input.Template)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	command, err := template.Render(input.Arguments)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	if err := s.policy.AuthorizeCommand(s.cfg, profile, command, template.ReadOnly); err != nil {
		_ = s.record(audit.Event{Action: "run-command-template", Profile: profile.Name, Command: command, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return nil, remote.CommandResult{}, fmt.Errorf("policy denied command template: %w", err)
	}
	decision := "allowed"
	if !template.ReadOnly || template.RequiresApproval {
		var pending *mcp.CallToolResult
		decision, pending, err = s.requireApproval(ctx, req, profile, "template", command, commandApprovalBinding(command, input.TTY, input.Stdin), template.RequiresApproval)
		if err != nil {
			return nil, remote.CommandResult{}, err
		}
		if pending != nil {
			return pending, remote.CommandResult{}, nil
		}
	}
	return s.execute(ctx, profile, commandInput{Profile: profile.Name, Command: command, TTY: input.TTY, Stdin: input.Stdin}, "run-command-template", decision)
}

func (s *Service) diagnoseConnection(ctx context.Context, _ *mcp.CallToolRequest, input profileInput) (*mcp.CallToolResult, remote.DiagnosticResult, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return nil, remote.DiagnosticResult{}, err
	}
	result := s.backend.Diagnose(ctx, profile)
	outcome := "failed"
	if result.Success {
		outcome = "completed"
	}
	_ = s.record(audit.Event{Action: "diagnose-connection", Profile: profile.Name, Decision: "allowed", Outcome: outcome})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: formatDiagnostics(result)}}, IsError: !result.Success}, result, nil
}

func formatDiagnostics(result remote.DiagnosticResult) string {
	var b strings.Builder
	for _, step := range result.Steps {
		status := "OK"
		if !step.OK {
			status = "FAILED"
		}
		fmt.Fprintf(&b, "[%s] %s (%dms): %s\n", status, step.Name, step.DurationMS, step.Message)
	}
	if result.ServerHostKey != "" {
		fmt.Fprintf(&b, "Server host key: %s\n", result.ServerHostKey)
	}
	return strings.TrimSpace(b.String())
}

type backgroundCommandInput struct {
	Command string `json:"command" jsonschema:"shell command to execute"`
	Profile string `json:"profile,omitempty" jsonschema:"profile name; omit to use defaults.defaultProfile"`
	TTY     bool   `json:"tty,omitempty"`
	Stdin   string `json:"stdin,omitempty"`
}

type startCommandOutput struct {
	Job jobs.Job `json:"job"`
}

type taskCapture struct{ job *jobs.Job }
type taskCaptureKey struct{}

func (s *Service) startCommand(ctx context.Context, req *mcp.CallToolRequest, input backgroundCommandInput) (*mcp.CallToolResult, startCommandOutput, error) {
	job, err := s.startBackground(ctx, req, input)
	if err != nil {
		if pending, ok := errors.AsType[*approvalPendingError](err); ok {
			return pending.result, startCommandOutput{}, nil
		}
		return nil, startCommandOutput{}, err
	}
	if capture, _ := ctx.Value(taskCaptureKey{}).(*taskCapture); capture != nil {
		capture.job = &job
	}
	output := startCommandOutput{Job: job}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Started background job %s on %s", job.ID, job.Profile)}}}, output, nil
}

func (s *Service) startBackground(ctx context.Context, req *mcp.CallToolRequest, input backgroundCommandInput) (jobs.Job, error) {
	profile, err := s.cfg.Profile(input.Profile)
	if err != nil {
		return jobs.Job{}, err
	}
	if err := allowArbitraryCommand(profile); err != nil {
		_ = s.record(audit.Event{Action: "start-command", Profile: profile.Name, Command: input.Command, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return jobs.Job{}, err
	}
	if err := s.policy.AuthorizeCommand(s.cfg, profile, input.Command, false); err != nil {
		_ = s.record(audit.Event{Action: "start-command", Profile: profile.Name, Command: input.Command, Decision: "denied", Outcome: "not-run", Error: err.Error()})
		return jobs.Job{}, fmt.Errorf("policy denied start-command: %w", err)
	}
	if int64(len(input.Stdin)) > s.cfg.TransferLimit(profile) {
		return jobs.Job{}, fmt.Errorf("stdin is %d bytes; profile transfer limit is %d", len(input.Stdin), s.cfg.TransferLimit(profile))
	}
	command := strings.TrimSpace(input.Command)
	decision, pending, err := s.requireApproval(ctx, req, profile, "background-command", command, commandApprovalBinding(command, input.TTY, input.Stdin), false)
	if err != nil {
		return jobs.Job{}, err
	}
	if pending != nil {
		return jobs.Job{}, &approvalPendingError{result: pending}
	}
	var token any
	if req != nil && !clientSupportsTasks(req) {
		token = req.Params.GetProgressToken()
	}
	notify := func(job jobs.Job) {
		if token == nil || req.Session == nil {
			return
		}
		progress := 0.0
		if job.Status != jobs.Working {
			progress = 1
		}
		notifyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = req.Session.NotifyProgress(notifyCtx, &mcp.ProgressNotificationParams{ProgressToken: token, Progress: progress, Total: 1, Message: job.StatusMessage})
	}
	job, err := s.jobs.Start(profile.Name, command, func(runCtx context.Context) (remote.CommandResult, error) {
		started := time.Now()
		result, runErr := s.backend.Run(runCtx, profile, command, remote.RunOptions{
			TTY: input.TTY, Stdin: input.Stdin,
			Timeout: time.Duration(s.cfg.CommandTimeout(profile)) * time.Millisecond, OutputLimit: s.cfg.OutputLimit(profile),
		})
		event := audit.Event{Action: "start-command", Profile: profile.Name, Command: command, Decision: decision, DurationMS: time.Since(started).Milliseconds()}
		if runErr != nil {
			event.Outcome, event.Error = "failed", runErr.Error()
		} else {
			exit := result.ExitCode
			event.ExitCode, event.Outcome, event.Error = &exit, commandOutcome(result), result.Error
		}
		_ = s.record(event)
		return result, runErr
	}, notify)
	return job, err
}

type jobInput struct {
	JobID string `json:"jobId"`
}
type jobOutput struct {
	Job jobs.Job `json:"job"`
}

func (s *Service) jobStatus(_ context.Context, _ *mcp.CallToolRequest, input jobInput) (*mcp.CallToolResult, jobOutput, error) {
	job, err := s.jobs.Get(input.JobID)
	return nil, jobOutput{Job: job}, err
}

func (s *Service) jobOutput(_ context.Context, _ *mcp.CallToolRequest, input jobInput) (*mcp.CallToolResult, remote.CommandResult, error) {
	job, err := s.jobs.Get(input.JobID)
	if err != nil {
		return nil, remote.CommandResult{}, err
	}
	if job.Status == jobs.Working {
		return nil, remote.CommandResult{}, fmt.Errorf("job %q is still running", job.ID)
	}
	if job.Result == nil {
		return nil, remote.CommandResult{}, fmt.Errorf("job %q has no command result: %s", job.ID, job.Error)
	}
	result := *job.Result
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: formatCommandResult(result)}}, IsError: result.ExitCode != 0 || result.Error != ""}, result, nil
}

func (s *Service) cancelJob(_ context.Context, _ *mcp.CallToolRequest, input jobInput) (*mcp.CallToolResult, jobOutput, error) {
	job, err := s.jobs.Cancel(input.JobID)
	if err != nil {
		return nil, jobOutput{}, err
	}
	_ = s.record(audit.Event{Action: "cancel-job", Profile: job.Profile, Target: job.ID, Decision: "allowed", Outcome: "requested"})
	return nil, jobOutput{Job: job}, nil
}

// Stable Tasks extension wire types (2026-07-28).
type taskParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

type updateTaskParams struct {
	mcp.ParamsBase
	TaskID         string         `json:"taskId"`
	InputResponses map[string]any `json:"inputResponses"`
}

type taskResult struct {
	mcp.ResultBase
	ResultType    string         `json:"resultType"`
	TaskID        string         `json:"taskId"`
	Status        jobs.Status    `json:"status"`
	StatusMessage string         `json:"statusMessage,omitempty"`
	CreatedAt     string         `json:"createdAt"`
	LastUpdatedAt string         `json:"lastUpdatedAt"`
	TTLMS         int64          `json:"ttlMs"`
	PollInterval  int            `json:"pollIntervalMs,omitempty"`
	Result        map[string]any `json:"result,omitempty"`
	Error         map[string]any `json:"error,omitempty"`
}

type taskAck struct {
	mcp.ResultBase
	ResultType string `json:"resultType"`
}

func (s *Service) registerTaskMethods(server *mcp.Server) {
	mustRegister := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	mustRegister(mcp.AddReceivingCustomMethod(server, "tasks/get", func(_ context.Context, session *mcp.ServerSession, params *taskParams) (*taskResult, error) {
		if err := requireTasksCapability(session); err != nil {
			return nil, err
		}
		job, err := s.jobs.Get(params.TaskID)
		if err != nil {
			return nil, invalidTaskError(err)
		}
		return detailedTask(job), nil
	}))
	mustRegister(mcp.AddReceivingCustomMethod(server, "tasks/cancel", func(_ context.Context, session *mcp.ServerSession, params *taskParams) (*taskAck, error) {
		if err := requireTasksCapability(session); err != nil {
			return nil, err
		}
		if _, err := s.jobs.Cancel(params.TaskID); err != nil {
			return nil, invalidTaskError(err)
		}
		return &taskAck{ResultType: "complete"}, nil
	}))
	mustRegister(mcp.AddReceivingCustomMethod(server, "tasks/update", func(_ context.Context, session *mcp.ServerSession, params *updateTaskParams) (*taskAck, error) {
		if err := requireTasksCapability(session); err != nil {
			return nil, err
		}
		if _, err := s.jobs.Get(params.TaskID); err != nil {
			return nil, invalidTaskError(err)
		}
		// Approvals happen before SSH execution starts, so this server currently
		// has no mid-flight input requests to satisfy.
		return &taskAck{ResultType: "complete"}, nil
	}))
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			call, ok := request.(*mcp.CallToolRequest)
			if !ok || method != "tools/call" || call.Params.Name != "start-command" || !clientSupportsTasks(call) {
				return next(ctx, method, request)
			}
			capture := &taskCapture{}
			result, err := next(context.WithValue(ctx, taskCaptureKey{}, capture), method, request)
			if err != nil || capture.job == nil {
				return result, err
			}
			return createTask(*capture.job), nil
		}
	})
}

func requireTasksCapability(session *mcp.ServerSession) error {
	if session != nil {
		if init := session.InitializeParams(); init != nil && init.Capabilities != nil {
			if _, ok := init.Capabilities.Extensions[tasksExtension]; ok {
				return nil
			}
		}
	}
	data, err := json.Marshal(mcp.MissingRequiredClientCapabilityData{
		RequiredCapabilities: &mcp.ClientCapabilities{Extensions: map[string]any{tasksExtension: map[string]any{}}},
	})
	if err != nil {
		return err
	}
	return &jsonrpc.Error{Code: mcp.CodeMissingRequiredClientCapabilities, Message: "tasks capability required but not declared by client", Data: data}
}

func invalidTaskError(err error) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}
}

func clientSupportsTasks(req *mcp.CallToolRequest) bool {
	caps := req.ClientCapabilities()
	if caps == nil {
		return false
	}
	_, ok := caps.Extensions[tasksExtension]
	return ok
}

func createTask(job jobs.Job) *taskResult {
	result := detailedTask(job)
	result.ResultType = "task"
	result.Result = nil
	result.Error = nil
	return result
}

func detailedTask(job jobs.Job) *taskResult {
	result := &taskResult{
		ResultType: "complete", TaskID: job.ID, Status: job.Status, StatusMessage: job.StatusMessage,
		CreatedAt: job.CreatedAt.Format(time.RFC3339Nano), LastUpdatedAt: job.LastUpdatedAt.Format(time.RFC3339Nano),
		TTLMS: job.TTLMS, PollInterval: job.PollIntervalMS,
	}
	if job.Status == jobs.Completed && job.Result != nil {
		content := formatCommandResult(*job.Result)
		result.Result = map[string]any{
			"content":           []map[string]any{{"type": "text", "text": content}},
			"structuredContent": job.Result,
			"isError":           job.Result.ExitCode != 0 || job.Result.Error != "",
		}
	} else if job.Status == jobs.Failed {
		result.Error = map[string]any{"code": -32603, "message": job.Error}
	}
	return result
}

type approvalPendingError struct{ result *mcp.CallToolResult }

func (*approvalPendingError) Error() string { return "approval input is required" }
