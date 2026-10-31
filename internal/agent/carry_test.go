package agent

import (
	"strings"
	"testing"
)

func TestAMountedRowCarriesWhetherTheAskWentOut(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) publishMounted", "\nfunc "))
	if !strings.Contains(body, "state.refused[volume].requested") {
		t.Error("a mounted row reports 'not yet asked' unconditionally, so " +
			"re-opening the image asks the same question from the start")
	}
}

// The menu can only say "Installing…" if the agent says a copy is running.
//
// Source-inspected rather than driven, because the copy itself is a `ditto`
// into /Applications and the thing worth pinning is the ORDER: marked before
// the copy, cleared after it. Marking afterwards would set a flag that is
// only ever true once the work it describes is already over.
func TestACopyInProgressIsAnnouncedBeforeItStartsNotAfterItEnds(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) requestApproval", "\nfunc "))

	before := strings.Index(body, "markInstalling(state, volume, true)")
	install := strings.Index(body, "installApproved(d)")
	after := strings.Index(body, "markInstalling(state, volume, false)")

	if before < 0 || after < 0 {
		t.Fatal("the agent no longer says when a copy is running, so the menu " +
			"goes on offering Install for the whole length of it and somebody " +
			"clicks it twice")
	}
	if !(before < install && install < after) {
		t.Errorf("the copy is not bracketed by the announcement "+
			"(mark=%d install=%d clear=%d)", before, install, after)
	}
}

// And a volume that goes away takes its in-progress flag with it, or a crash
// mid-copy leaves the menu saying "Installing…" about an image nobody can
// see, for as long as the agent runs.
func TestForgettingAVolumeForgetsThatItWasBeingInstalled(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) rescanVolumes", "\nfunc "))
	if !strings.Contains(body, "delete(state.installing, volume)") {
		t.Error("an unmounted volume keeps its installing flag")
	}
}
