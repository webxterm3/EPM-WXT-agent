//go:build darwin

package main

import (
	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/remotecontrol/capture"
	"github.com/Yesveer/wxt-agent/internal/remotecontrol/input"
)

// requestOSPermissions registers this binary in System Settings and reports
// what it currently holds.
//
// The ASKING is the point, not the answer. macOS lists a binary under
// Accessibility or Screen Recording only once that binary has requested the
// right — so until this call existed the lists never mentioned wxt-agent-session
// and the only way to grant anything was to know to press "+" and find a
// binary under /usr/local/bin.
//
// Both are asked for here rather than at the moment each is first needed, so
// one visit to Settings covers both.
//
// Never fatal. A helper with neither grant still runs and reports the refusal
// through the session, which is how the portal can say "this Mac needs
// permission" rather than "remote control failed".
func requestOSPermissions(logger *zap.Logger) {
	accessibility := input.RequestAccessibility()
	screen := capture.RequestScreenRecording()

	logger.Info("macOS permissions",
		zap.Bool("accessibility", accessibility),
		zap.Bool("screen_recording", screen))

	if !accessibility || !screen {
		// One actionable line rather than two warnings: the fix is a single
		// visit to one settings pane.
		logger.Warn("Remote control needs permission that has not been granted yet",
			zap.Bool("accessibility_granted", accessibility),
			zap.Bool("screen_recording_granted", screen),
			zap.String("fix", "System Settings › Privacy & Security — switch on wxt-agent-session under Accessibility and Screen Recording. Both entries are listed there once this has run."))
	}
}
