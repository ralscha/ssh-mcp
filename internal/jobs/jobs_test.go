package jobs

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ssh-mcp/internal/remote"
)

func TestJobCompletesAndPersists(t *testing.T) {
	state := filepath.Join(t.TempDir(), "jobs.json")
	m, err := New(state, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	job, err := m.Start("dev", "ignored", func(context.Context) (remote.CommandResult, error) {
		return remote.CommandResult{Profile: "dev", Stdout: "ok", ExitCode: 0}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = m.Get(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == Completed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if job.Status != Completed || job.Result == nil || job.Result.Stdout != "ok" {
		t.Fatalf("job did not complete: %+v", job)
	}
	reloaded, err := New(state, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reloaded.Get(job.ID); err != nil || got.Status != Completed {
		t.Fatalf("reloaded job = %+v, %v", got, err)
	}
}

func TestToolErrorResultIsACompletedTask(t *testing.T) {
	m, err := New("", time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	job, err := m.Start("dev", "false", func(context.Context) (remote.CommandResult, error) {
		return remote.CommandResult{Profile: "dev", ExitCode: 1, Error: "remote command failed"}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = m.Get(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != Working {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if job.Status != Completed || job.Result == nil || job.Result.ExitCode != 1 {
		t.Fatalf("job = %+v, want completed tool error", job)
	}
}
