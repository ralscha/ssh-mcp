package server

import "testing"

func TestApplyUnifiedPatch(t *testing.T) {
	original := "one\ntwo\nthree\n"
	patch := "--- a/file\n+++ b/file\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"
	got, err := applyUnifiedPatch(original, patch)
	if err != nil {
		t.Fatal(err)
	}
	if got != "one\nTWO\nthree\n" {
		t.Fatalf("patched = %q", got)
	}
}

func TestApplyUnifiedPatchRejectsStaleContext(t *testing.T) {
	_, err := applyUnifiedPatch("changed\n", "@@ -1 +1 @@\n-old\n+new\n")
	if err == nil {
		t.Fatal("stale patch was accepted")
	}
}
