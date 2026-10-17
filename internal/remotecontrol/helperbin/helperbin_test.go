package helperbin

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// These tests run against a plain `go test` build, which embeds the committed
// placeholder rather than a real helper — so the not-embedded path is what the
// package-level functions exercise, and the write logic is driven through
// extractTo with fake payloads.

func TestPlaceholderIsNotTreatedAsAHelper(t *testing.T) {
	// This checks placeholder DETECTION, so it only applies to a build that
	// carries the placeholder — a Makefile build embeds a real helper and has
	// nothing to detect.
	if len(helper) > 0 && !bytes.HasPrefix(helper, []byte(placeholderMarker)) {
		t.Skip("this build embeds a real helper")
	}

	// The whole point of the marker: an agent built without the Makefile's
	// inject step must NOT extract 600 bytes of prose and call it an
	// executable. Getting this wrong produces a helper that launchd or
	// CreateProcess refuses, with no clue why.
	if Available() {
		t.Fatal("the committed placeholder was mistaken for a real helper")
	}
	if got := Size(); got != 0 {
		t.Errorf("Size() = %d with no helper embedded, want 0", got)
	}
	if got := SHA256(); got != "" {
		t.Errorf("SHA256() = %q with no helper embedded, want empty", got)
	}
}

func TestExtractRefusesWhenNothingIsEmbedded(t *testing.T) {
	if Available() {
		t.Skip("this build embeds a real helper")
	}
	_, err := Extract(filepath.Join(t.TempDir(), "helper"))
	if !errors.Is(err, ErrNotEmbedded) {
		t.Fatalf("Extract error = %v, want ErrNotEmbedded", err)
	}
}
