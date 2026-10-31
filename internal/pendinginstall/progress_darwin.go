//go:build darwin

package pendinginstall

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Saying how far along an install is, honestly.
//
// "Honestly" is the whole difficulty. An indeterminate bar answers "is
// anything happening" and nothing else, and somebody watching a 400MB copy
// wants to know whether to wait thirty seconds or give up. But a bar that
// moves because time is passing, rather than because work is being done, is
// worse than no bar: it promises an estimate and delivers a guess, and the
// moment it sits at 90% for a minute nobody believes any bar again.
//
// So each of the two kinds of install is measured by whatever it genuinely
// exposes, and where nothing is exposed the bar stays indeterminate rather
// than being invented.
//
//   - A BUNDLE is copied by ditto, which reports nothing at all. What IS
//     knowable is how big the source is and how big the destination has got,
//     and the ratio of those is a real measurement of real work.
//   - A PACKAGE is run by installer, which with -verboseR prints its own
//     percentage and the name of each phase. Measured on this platform:
//     "installer:%97.750000" and "installer:PHASE:Finishing the
//     Installation…". That is the installer's own account of itself and
//     beats anything observed from outside.

// Progress is one report about work in flight. Total of 0 means the size is
// not knowable, which keeps the bar indeterminate.
type Progress struct {
	Phase       string
	Done, Total int64
}

// progressSink is told how far along the current install is.
//
// A package-level hook rather than an argument threaded through every
// install function: the reporting is a side channel to a user interface,
// not part of deciding or doing the install, and every caller that does not
// care would otherwise have to carry a parameter it ignores.
var (
	progressMu   sync.Mutex
	progressSink func(Progress)
)

// SetProgressSink installs the reporter. Passing nil turns reporting off.
func SetProgressSink(f func(Progress)) {
	progressMu.Lock()
	defer progressMu.Unlock()
	progressSink = f
}

// report tells the sink, if there is one. Safe to call from anywhere.
func report(p Progress) {
	progressMu.Lock()
	f := progressSink
	progressMu.Unlock()
	if f != nil {
		f(p)
	}
}

// progressTick is how often the copy's size is re-measured.
//
// Fast enough that the bar moves rather than steps — the menu bar redraws
// four times a second, so anything slower than this would leave it drawing
// the same number twice. A directory walk of a staging copy is a stat per
// file and costs far less than the copy it is watching.
const progressTick = 200 * time.Millisecond

// treeSize adds up every regular file under a path.
//
// Errors are swallowed on purpose. This runs against a tree another process
// is actively writing, so files appear and vanish between the walk deciding
// to visit one and getting there; treating that as a failure would make the
// measurement fail precisely when it is working.
func treeSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // a tree being written to is not an error
		}
		total += info.Size()
		return nil
	})
	return total
}

// watchCopy reports the growing size of dst against the known size of src
// until the context is cancelled.
//
// The total is measured ONCE, before the copy starts, and from the SOURCE.
// Measuring the destination's eventual size would require knowing the answer
// already, and re-measuring the source during the copy would spend the whole
// budget walking a disk image for a number that cannot change.
func watchCopy(ctx context.Context, src, dst string, phase string) {
	total := treeSize(src)
	report(Progress{Phase: phase, Done: 0, Total: total})

	ticker := time.NewTicker(progressTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report(Progress{Phase: phase, Done: treeSize(dst), Total: total})
		}
	}
}
