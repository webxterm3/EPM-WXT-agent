// Package helperbin carries the session helper inside the agent binary.
//
// Remote control needs two executables on the machine — the agent daemon and a
// helper that runs inside the user's desktop — but asking an operator to
// download two files, match their architectures and keep them in the same
// folder produced exactly the failures it sounds like it would. Embedding the
// helper makes the agent a single self-contained download: it writes the
// helper out during configure, and again at session start if it has gone
// missing.
//
// The embedded bytes are platform-specific, so the Makefile builds the helper
// for each target and drops it into helper.bin immediately before building the
// agent for that same target.
package helperbin

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"

	"github.com/Yesveer/wxt-agent/internal/embedbin"
)

//go:embed helper.bin
var helper []byte

// placeholderMarker identifies the committed stand-in that exists only so
// //go:embed has something to compile against. An agent built without the
// Makefile's inject step embeds that text, and extracting it would produce a
// file that is not an executable at all — so it is detected and treated as
// "nothing embedded" instead.
const placeholderMarker = "WXT-HELPER-PLACEHOLDER"

// ErrNotEmbedded means this build carries no helper. Callers fall back to
// looking for one on disk.
var ErrNotEmbedded = errors.New("this agent build has no embedded session helper")

// Available reports whether a real helper is embedded.
func Available() bool {
	// The marker sits at the very start of the placeholder, so a prefix check
	// is enough and never scans a 7 MB binary.
	return len(helper) > len(placeholderMarker) &&
		!bytes.HasPrefix(helper, []byte(placeholderMarker))
}

// Size is the embedded helper's size in bytes, or zero when none is embedded.
func Size() int {
	if !Available() {
		return 0
	}
	return len(helper)
}

// SHA256 is the hex digest of the embedded helper, used to tell an up-to-date
// extraction from a stale one left by an earlier agent version.
func SHA256() string {
	if !Available() {
		return ""
	}
	sum := sha256.Sum256(helper)
	return hex.EncodeToString(sum[:])
}

// Extract writes the embedded helper to path, creating parent directories as
// needed. It returns the path written.
//
// An existing file with identical contents is left alone — rewriting it on
// every agent start would churn the file for no reason and, on macOS, risks
// invalidating the TCC grant the user already gave it. Anything else is
// replaced, which is how an agent upgrade carries a new helper with it.
func Extract(path string) (string, error) {
	if !Available() {
		return "", ErrNotEmbedded
	}
	return embedbin.ExtractTo(path, helper)
}
