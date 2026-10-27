//go:build darwin

package pendinginstall

import (
	"errors"
	"testing"
)

// stubDetach records each attempt and answers from a script.
func stubDetach(t *testing.T, answers []error) *[]bool {
	t.Helper()
	origDetach, origPause := detachVolume, ejectRetryPause

	var forced []bool
	i := 0
	detachVolume = func(volume string, force bool) error {
		forced = append(forced, force)
		if i < len(answers) {
			err := answers[i]
			i++
			return err
		}
		return nil
	}
	ejectRetryPause = func() {}

	t.Cleanup(func() { detachVolume, ejectRetryPause = origDetach, origPause })
	return &forced
}

var busy = errors.New("Resource busy")

// Finder holds a volume whose window is open — and that window is open,
// because opening it is what somebody just did. Leaving the image mounted is
// not a neutral outcome: the next thing that happens is the drag, and the
// drag without a window onto /Applications is the administrator password
// sheet this whole feature exists to remove.
func TestAnImageFinderIsHoldingIsStillClosed(t *testing.T) {
	forced := stubDetach(t, []error{busy, busy}) // both gentle attempts refused

	if err := Eject("/Volumes/Visual Studio Code"); err != nil {
		t.Fatalf("the image stayed mounted: %v", err)
	}
	if len(*forced) != 3 {
		t.Fatalf("made %d attempts, wanted gentle, gentle, forced", len(*forced))
	}
	if (*forced)[0] || (*forced)[1] {
		t.Error("forced before asking nicely — a forced detach shows the person " +
			"a \"disk not ejected properly\" notice they did not need to see")
	}
	if !(*forced)[2] {
		t.Error("gave up instead of forcing, so the password sheet is what happens next")
	}
}

// A volume that lets go on the first ask is never forced.
func TestAnImageThatClosesPolitelyIsNotForced(t *testing.T) {
	forced := stubDetach(t, nil) // first attempt succeeds

	if err := Eject("/Volumes/Zoom"); err != nil {
		t.Fatalf("eject failed: %v", err)
	}
	if len(*forced) != 1 || (*forced)[0] {
		t.Errorf("attempts were %v, wanted exactly one gentle one", *forced)
	}
}

// Finder often lets go a moment after refusing once.
func TestASecondPoliteAskIsTriedBeforeForcing(t *testing.T) {
	forced := stubDetach(t, []error{busy})

	if err := Eject("/Volumes/Slack"); err != nil {
		t.Fatalf("eject failed: %v", err)
	}
	if len(*forced) != 2 {
		t.Fatalf("made %d attempts, wanted two", len(*forced))
	}
	if (*forced)[1] {
		t.Error("forced on the second attempt instead of asking nicely again")
	}
}
