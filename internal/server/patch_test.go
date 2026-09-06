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

func TestApplyUnifiedPatchInsertionUsesZeroLengthRangePosition(t *testing.T) {
	got, err := applyUnifiedPatch("one\ntwo\n", "@@ -1,0 +2 @@\n+inserted\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "one\ninserted\ntwo\n" {
		t.Fatalf("patched = %q", got)
	}
}

func TestApplyUnifiedPatchHeaderLikeContent(t *testing.T) {
	got, err := applyUnifiedPatch("-- heading\nold\n", "@@ -1,2 +1,2 @@\n--- heading\n+-- heading\n-old\n+++ heading\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "-- heading\n++ heading\n" {
		t.Fatalf("patched = %q", got)
	}
}

func TestApplyUnifiedPatchFinalNewlineMarkers(t *testing.T) {
	tests := []struct {
		name     string
		original string
		patch    string
		want     string
	}{
		{
			name:     "old lacked newline but replacement gains one",
			original: "old",
			patch:    "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n",
			want:     "new\n",
		},
		{
			name:     "replacement loses newline",
			original: "old\n",
			patch:    "@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n",
			want:     "new",
		},
		{
			name:     "deleting unterminated last line reveals prior newline",
			original: "one\ntwo",
			patch:    "@@ -2 +1,0 @@\n-two\n\\ No newline at end of file\n",
			want:     "one\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := applyUnifiedPatch(test.original, test.patch)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("patched = %q, want %q", got, test.want)
			}
		})
	}
}

func TestApplyUnifiedPatchRejectsMultipleFilesAndInconsistentLineNumbers(t *testing.T) {
	patches := []string{
		"--- a/one\n+++ b/one\n@@ -1 +1 @@\n-old\n+new\n--- a/two\n+++ b/two\n@@ -1 +1 @@\n-old\n+new\n",
		"@@ -1 +2 @@\n-old\n+new\n",
	}
	for _, patch := range patches {
		if _, err := applyUnifiedPatch("old\n", patch); err == nil {
			t.Fatalf("malformed patch was accepted: %q", patch)
		}
	}
}
