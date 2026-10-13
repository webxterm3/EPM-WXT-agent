package remotecontrol

import (
	"errors"
	"testing"
)

// The bug this pins: the helper answers the start request with "awaiting
// consent" and only finds out it has no grant afterwards, when it tries to
// capture. So the refusal arrives as an EVENT, long after the call that
// started the session returned successfully — and the check that looked at
// that call's error never saw one. Nothing dropped the helper, nothing watched
// for the grant, and the agent never restarted itself.
func TestRefusalTextFromAnEventIsRecognised(t *testing.T) {
	// Verbatim from a machine that could not start a session.
	for _, msg := range []string{
		"capture: darwin: macOS denied screen capture. Switch on wxt-agent.app in System Settings › Privacy & Security › Screen Recording. (the process asking is /Applications/wxt-agent.app/Contents/MacOS/wxt-agent-session) (The user declined TCCs for application, window, display capture)",
		"input: darwin: macOS denied input control. Switch on wxt-agent.app in System Settings › Privacy & Security › Accessibility. (the process asking is /Applications/wxt-agent.app/Contents/MacOS/wxt-agent-session)",
	} {
		if !isPermissionDenied(errors.New(msg)) {
			t.Errorf("a real refusal was not recognised, so nothing would react to it:\n  %s", msg)
		}
	}
}

// The other terminal states must NOT trigger a restart. Somebody declining the
// consent prompt is a normal outcome, and restarting the agent for it would be
// baffling.
func TestOrdinaryFailuresDoNotLookLikeRefusals(t *testing.T) {
	for _, msg := range []string{
		"the user did not approve the session",
		"consent timed out",
		"the session helper is not connected",
		"ipc: start timed out",
	} {
		if isPermissionDenied(errors.New(msg)) {
			t.Errorf("treated as a permission refusal, so the agent would restart for nothing:\n  %s", msg)
		}
	}
}
