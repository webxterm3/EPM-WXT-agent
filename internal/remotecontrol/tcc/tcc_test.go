package tcc

import (
	"strings"
	"testing"
)

// The message has to name the row System Settings actually shows, and there is
// now exactly one of them.
//
// The helper is signed with the application's bundle identifier, so macOS sees
// the whole product as one code identity and lists it once under the product
// name with the product icon. Earlier builds gave each binary its own
// identifier, which produced a row per binary per path under bare file names —
// and people added three of them by hand, none of which was the one asking.
func TestMessageNamesTheSingleProductRow(t *testing.T) {
	msg := DeniedMessage("Accessibility", "macOS denied input control")

	want := "Switch on " + ProductRowName
	if !strings.Contains(msg, want) {
		t.Errorf("the message does not tell somebody to switch on the product row.\nwant to find: %s\ngot:\n%s",
			want, msg)
	}
	if !strings.Contains(msg, "product icon") {
		t.Errorf("the message does not say which row to pick when several are listed:\n%s", msg)
	}
	if !strings.Contains(msg, "nothing else to add") {
		t.Errorf("the message does not say that one row is enough, so somebody keeps adding binaries:\n%s", msg)
	}
}

// Somebody reading this has already been granting permissions one binary at a
// time, and those leftover rows are still in the list confusing them.
func TestMessageSaysToRemoveTheLeftoverRows(t *testing.T) {
	msg := DeniedMessage("Screen Recording", "macOS denied screen capture")

	for _, phrase := range []string{"blank icon", "wxt-agent-menubar", "grant nothing"} {
		if !strings.Contains(msg, phrase) {
			t.Errorf("the message does not explain the leftover rows (missing %q):\n%s", phrase, msg)
		}
	}
}

// The full path still has to be there: it is the only way to find the binary
// with "+" if the row is somehow missing, and it is what somebody pastes into
// a support conversation.
func TestMessageStillGivesTheProcessPath(t *testing.T) {
	msg := DeniedMessage("Accessibility", "x")
	self := selfPath()
	if self == "" {
		t.Skip("the running executable could not be resolved")
	}
	if !strings.Contains(msg, self) {
		t.Errorf("the message does not say which process asked:\n%s", msg)
	}
}

func TestMessageNamesTheSettingsPane(t *testing.T) {
	for _, right := range []string{"Accessibility", "Screen Recording"} {
		msg := DeniedMessage(right, "macOS denied something")
		if !strings.Contains(msg, "System Settings › Privacy & Security › "+right) {
			t.Errorf("the message does not say where to go for %q:\n%s", right, msg)
		}
	}
}

// macOS prompts once per binary and never again. Somebody who dismissed it
// has no way back unless the message says so.
func TestMessageWarnsThatThePromptDoesNotReturn(t *testing.T) {
	msg := DeniedMessage("Accessibility", "x")
	if !strings.Contains(msg, "only once") {
		t.Errorf("the message does not warn that a dismissed prompt never reappears:\n%s", msg)
	}
}
