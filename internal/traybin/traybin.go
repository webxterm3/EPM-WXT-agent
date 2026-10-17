// Package traybin carries the status-area program inside the agent binary.
//
// The same reasoning as helperbin, and for the same reason it exists: the
// agent ships as ONE downloadable file. Asking somebody to fetch a second
// executable, match its architecture and keep it in the right folder is a
// thing that does not happen — the first report of this feature was
// "could not install the tray icon: the tray program is not beside the agent",
// from a machine where exactly that had been downloaded on its own.
//
// The embedded bytes are platform-specific, so the Makefile builds the tray
// program for each target and drops it into tray.bin immediately before
// building the agent for that same target.
package traybin

import (
	"bytes"
	_ "embed"
	"errors"

	"github.com/Yesveer/wxt-agent/internal/embedbin"
)

//go:embed tray.bin
var tray []byte

// placeholderMarker identifies the committed stand-in that exists only so
// //go:embed has something to compile against.
const placeholderMarker = "WXT-TRAY-PLACEHOLDER"

// ErrNotEmbedded means this build carries no status-area program.
var ErrNotEmbedded = errors.New("this agent build has no embedded tray program")

// Available reports whether a real program is embedded.
func Available() bool {
	return len(tray) > len(placeholderMarker) &&
		!bytes.HasPrefix(tray, []byte(placeholderMarker))
}

// Size is the embedded program's size in bytes, or zero when none is embedded.
func Size() int {
	if !Available() {
		return 0
	}
	return len(tray)
}

// Extract writes the embedded program to path, creating parent directories as
// needed. An existing identical file is left alone.
func Extract(path string) (string, error) {
	if !Available() {
		return "", ErrNotEmbedded
	}
	return embedbin.ExtractTo(path, tray)
}
