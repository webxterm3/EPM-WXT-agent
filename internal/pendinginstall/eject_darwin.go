//go:build darwin

package pendinginstall

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Closing an image nothing can be installed from.
//
// The agent holds exactly one lever over Finder: an access-control entry on
// /Applications. Withholding it IS the administrator-password sheet —
// /Applications is root:admin 775, and that sheet is Finder's fallback when
// a standard user cannot write there. Granting it lets the copy run to
// completion and leaves the removal to happen afterwards, which is a
// progress bar followed by an application disappearing.
//
// So neither of those can give "no password prompt AND no copy", and the
// only remaining way to refuse a drag without either is for there to be
// nothing to drag. The image is closed, and the person is told why and
// offered the approval route — which still works, because the decision
// outlives the volume.

// Eject closes a mounted image.
//
// Graceful first, then forced. Finder holds a volume whose window is open —
// and that window is open, because opening it is what somebody just did —
// so a plain detach frequently reports the volume as busy. Leaving it
// mounted is not a neutral outcome: the next thing that happens is the drag,
// and the drag without a window onto /Applications is the administrator
// password sheet this exists to remove.
//
// Forcing is safe HERE specifically, and only here. This is called for
// software that is not installable, which means no access-control entry was
// granted, which means nothing can be part-way through copying into
// /Applications — there is nowhere for it to be copying TO. A forced detach
// can therefore interrupt a read, not a write.
func Eject(volume string) error {
	if err := detachVolume(volume, false); err == nil {
		return nil
	}
	// One more gentle attempt: Finder often lets go a moment after the
	// first refusal, and a forced detach that was not needed still shows the
	// person a "disk not ejected properly" notice.
	ejectRetryPause()
	if err := detachVolume(volume, false); err == nil {
		return nil
	}
	return detachVolume(volume, true)
}

// Seams. A test that really detached a volume on the machine running it
// would be a test nobody dares run, and one that really slept would make the
// suite a second slower for nothing.
var (
	detachVolume    = detach
	ejectRetryPause = func() { time.Sleep(time.Second) }
)

func detach(volume string, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{"detach", volume}
	if force {
		args = append(args, "-force")
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", args...).CombinedOutput()
	if err != nil {
		return &ejectError{volume: volume, detail: strings.TrimSpace(string(out)), err: err}
	}
	return nil
}

type ejectError struct {
	volume string
	detail string
	err    error
}

func (e *ejectError) Error() string {
	if e.detail != "" {
		return "could not close " + e.volume + ": " + e.detail
	}
	return "could not close " + e.volume + ": " + e.err.Error()
}

func (e *ejectError) Unwrap() error { return e.err }
