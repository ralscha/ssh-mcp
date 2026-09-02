package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestShellQuote(t *testing.T) {
	got := shellQuote("/srv/it's here")
	want := `'/srv/it'"'"'s here'`
	if got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

func TestFilterAgentSignersByFingerprint(t *testing.T) {
	signers := make([]ssh.Signer, 0, 2)
	for range 2 {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	want := ssh.FingerprintSHA256(signers[1].PublicKey())
	got := filterSigners(signers, want)
	if len(got) != 1 || ssh.FingerprintSHA256(got[0].PublicKey()) != want {
		t.Fatalf("filtered signers = %v, want only %s", got, want)
	}
}

func TestOutputCaptureUsesSharedLimit(t *testing.T) {
	capture := newOutputCapture(7)
	stdout := capture.writer(false)
	stderr := capture.writer(true)
	if _, err := stdout.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	gotOut, gotErr, truncated := capture.values()
	if gotOut != "hello" || gotErr != "wo" || !truncated {
		t.Fatalf("capture = (%q, %q, %v), want (hello, wo, true)", gotOut, gotErr, truncated)
	}
}

func TestProfileEnvironment(t *testing.T) {
	if got := profileEnvironment("prod-web.1", "PASSWORD"); got != "SSH_MCP_PROD_WEB_1_PASSWORD" {
		t.Fatalf("profileEnvironment() = %q", got)
	}
}

func TestWithWorkdir(t *testing.T) {
	got := withWorkdir("/srv/it's here", "pwd")
	want := `cd -- '/srv/it'"'"'s here' && pwd`
	if got != want {
		t.Fatalf("withWorkdir() = %q, want %q", got, want)
	}
}

func TestIsConnectionFailure(t *testing.T) {
	if !isConnectionFailure(io.EOF) || !isConnectionFailure(errors.New("ssh: connection is shut down")) {
		t.Fatal("connection failures were not recognized")
	}
	if isConnectionFailure(errors.New("ssh: rejected: resource shortage")) {
		t.Fatal("channel rejection was mistaken for a dead connection")
	}
}
