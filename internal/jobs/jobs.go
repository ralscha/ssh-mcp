// Package jobs manages bounded, cancellable, persistently indexed SSH jobs.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"ssh-mcp/internal/remote"
)

const PollIntervalMS = 1000

type Status string

const (
	Working   Status = "working"
	Completed Status = "completed"
	Failed    Status = "failed"
	Cancelled Status = "cancelled"
)

type Job struct {
	ID             string                `json:"taskId"`
	Status         Status                `json:"status"`
	StatusMessage  string                `json:"statusMessage,omitempty"`
	Profile        string                `json:"profile"`
	CreatedAt      time.Time             `json:"createdAt"`
	LastUpdatedAt  time.Time             `json:"lastUpdatedAt"`
	TTLMS          int64                 `json:"ttlMs"`
	PollIntervalMS int                   `json:"pollIntervalMs"`
	Result         *remote.CommandResult `json:"result,omitempty"`
	Error          string                `json:"error,omitempty"`
	Command        string                `json:"-"`
	cancel         context.CancelFunc
}

type Runner func(context.Context) (remote.CommandResult, error)
type Notify func(Job)

type Manager struct {
	mu        sync.Mutex
	jobs      map[string]*Job
	stateFile string
	retention time.Duration
	maxJobs   int
}

func New(stateFile string, retention time.Duration, maxJobs int) (*Manager, error) {
	m := &Manager{jobs: make(map[string]*Job), stateFile: stateFile, retention: retention, maxJobs: maxJobs}
	if m.retention <= 0 {
		m.retention = 24 * time.Hour
	}
	if m.maxJobs <= 0 {
		m.maxJobs = 100
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Start(profile, command string, runner Runner, notify Notify) (Job, error) {
	m.mu.Lock()
	m.pruneLocked(time.Now().UTC())
	if len(m.jobs) >= m.maxJobs {
		m.mu.Unlock()
		return Job{}, fmt.Errorf("job limit of %d reached; wait for jobs to expire", m.maxJobs)
	}
	now := time.Now().UTC()
	id, err := randomID()
	if err != nil {
		m.mu.Unlock()
		return Job{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID: id, Status: Working, StatusMessage: "SSH command is running", Profile: profile,
		CreatedAt: now, LastUpdatedAt: now, TTLMS: m.retention.Milliseconds(), PollIntervalMS: PollIntervalMS,
		Command: command, cancel: cancel,
	}
	m.jobs[job.ID] = job
	if err := m.saveLocked(); err != nil {
		delete(m.jobs, job.ID)
		m.mu.Unlock()
		cancel()
		return Job{}, err
	}
	copy := clone(job)
	m.mu.Unlock()
	if notify != nil {
		notify(copy)
	}
	go m.run(ctx, job.ID, runner, notify)
	return copy, nil
}

func (m *Manager) run(ctx context.Context, id string, runner Runner, notify Notify) {
	result, runErr := runner(ctx)
	m.mu.Lock()
	job, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	job.LastUpdatedAt = time.Now().UTC()
	job.cancel = nil
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		job.Result = &result
		job.Status = Cancelled
		job.StatusMessage = "SSH command was cancelled"
	case runErr != nil:
		job.Status = Failed
		job.StatusMessage = "SSH command failed"
		job.Error = runErr.Error()
	default:
		job.Result = &result
		job.Status = Completed
		if result.ExitCode != 0 || result.Error != "" {
			job.StatusMessage = "SSH command completed with an error result"
		} else {
			job.StatusMessage = "SSH command completed"
		}
	}
	if err := m.saveLocked(); err != nil {
		job.Status = Failed
		job.StatusMessage = "SSH command finished, but its task state could not be persisted"
		job.Error = err.Error()
		job.Result = nil
	}
	copy := clone(job)
	m.mu.Unlock()
	if notify != nil {
		notify(copy)
	}
}

func (m *Manager) Get(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now().UTC())
	job, ok := m.jobs[id]
	if !ok {
		return Job{}, fmt.Errorf("unknown or expired job %q", id)
	}
	return clone(job), nil
}

func (m *Manager) List() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now().UTC())
	result := make([]Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		result = append(result, clone(job))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

func (m *Manager) Cancel(id string) (Job, error) {
	m.mu.Lock()
	job, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return Job{}, fmt.Errorf("unknown or expired job %q", id)
	}
	if job.Status != Working {
		copy := clone(job)
		m.mu.Unlock()
		return copy, nil
	}
	cancel := job.cancel
	job.StatusMessage = "Cancellation requested"
	job.LastUpdatedAt = time.Now().UTC()
	saveErr := m.saveLocked()
	copy := clone(job)
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if saveErr != nil {
		return copy, fmt.Errorf("persist cancellation request: %w", saveErr)
	}
	return copy, nil
}

func (m *Manager) load() error {
	if m.stateFile == "" {
		return nil
	}
	data, err := os.ReadFile(m.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read job state: %w", err)
	}
	var stored []*Job
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse job state: %w", err)
	}
	now := time.Now().UTC()
	for _, job := range stored {
		if job == nil || job.ID == "" || now.Sub(job.CreatedAt) > m.retention {
			continue
		}
		if job.Status == Working {
			job.Status = Failed
			job.StatusMessage = "Server restarted while the SSH command was running"
			job.Error = "job interrupted by server restart"
			job.LastUpdatedAt = now
		} else if job.Status == Completed && job.Result == nil {
			job.Status = Failed
			job.StatusMessage = "Persisted task result is missing"
			job.Error = "invalid persisted job state: completed job has no result"
			job.LastUpdatedAt = now
		}
		job.Command = ""
		job.cancel = nil
		m.jobs[job.ID] = job
	}
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if m.stateFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0o700); err != nil {
		return fmt.Errorf("create job state directory: %w", err)
	}
	stored := make([]*Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		copy := clone(job)
		stored = append(stored, &copy)
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode job state: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(m.stateFile), "."+filepath.Base(m.stateFile)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary job state: %w", err)
	}
	temporary := f.Name()
	removeTemporary := func() {
		_ = f.Close()
		_ = os.Remove(temporary)
	}
	if err := f.Chmod(0o600); err != nil {
		removeTemporary()
		return fmt.Errorf("secure job state permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		removeTemporary()
		return fmt.Errorf("write job state: %w", err)
	}
	if err := f.Sync(); err != nil {
		removeTemporary()
		return fmt.Errorf("sync job state: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("close job state: %w", err)
	}
	if err := os.Rename(temporary, m.stateFile); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("replace job state: %w", err)
	}
	return nil
}

func (m *Manager) pruneLocked(now time.Time) {
	changed := false
	for id, job := range m.jobs {
		if job.Status != Working && now.Sub(job.CreatedAt) > m.retention {
			delete(m.jobs, id)
			changed = true
		}
	}
	if changed {
		_ = m.saveLocked()
	}
}

func clone(job *Job) Job {
	copy := *job
	copy.cancel = nil
	if job.Result != nil {
		result := *job.Result
		copy.Result = &result
	}
	return copy
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate cryptographically secure job ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
