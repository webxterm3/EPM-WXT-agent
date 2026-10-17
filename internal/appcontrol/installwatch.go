package appcontrol

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
)

// installPollInterval is how often the places software lands are checked for
// change.
//
// This is what turns "a blocked application is removed within two minutes"
// into "it is gone almost as soon as it arrives". It exists because the
// reconcile pass is comparatively expensive — it walks application
// directories, reads property lists, reads the registry — and cannot be run
// every few seconds, while noticing that a directory changed is one stat per
// directory and costs nothing.
const installPollInterval = 8 * time.Second

// watchInstalls triggers a reconcile when software appears or disappears.
//
// Deliberately crude: it watches the modification time of the handful of
// directories installers actually write to, and asks for a pass when one of
// them moves. It does not care what changed — the reconcile pass works that
// out, and a few spurious passes cost far less than the file-system event
// machinery that would avoid them.
//
// A directory that does not exist is not an error and not a reason to stop
// watching: Homebrew's Caskroom appears the first time somebody installs a
// cask, and a machine that gains one mid-flight should still be covered.
func (e *Enforcer) watchInstalls(ctx context.Context) {
	dirs := installWatchDirs()
	if len(dirs) == 0 {
		return
	}
	e.logger.Debug("Application control: watching for new software",
		zap.Strings("directories", dirs),
		zap.Duration("interval", installPollInterval))

	seen := snapshotDirs(dirs)

	t := time.NewTicker(installPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := snapshotDirs(dirs)
			if sameSnapshot(seen, now) {
				continue
			}
			seen = now
			e.logger.Debug("Application control: something was installed or removed, reconciling")
			e.Kick()
		}
	}
}

// snapshotDirs records the modification time of each watched directory.
//
// A directory's mtime changes when an entry is added or removed from it, which
// is exactly the event worth reacting to. It does NOT change when something
// inside an existing entry changes, which is also correct — an application
// updating itself is not an install.
func snapshotDirs(dirs []string) map[string]time.Time {
	out := make(map[string]time.Time, len(dirs))
	for _, d := range dirs {
		fi, err := os.Stat(d)
		if err != nil {
			// Absent is a normal state and a meaningful one: a directory
			// appearing is itself a change, so it is recorded as the zero
			// time rather than skipped.
			out[d] = time.Time{}
			continue
		}
		out[d] = fi.ModTime()
	}
	return out
}

func sameSnapshot(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if other, ok := b[k]; !ok || !other.Equal(v) {
			return false
		}
	}
	return true
}
