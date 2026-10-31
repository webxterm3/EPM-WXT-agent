package agentstatus

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// How far along an install is, from the agent to the menu bar.
//
// A SEPARATE file from status.json, and from install-result, because it is
// written on a completely different cadence. The status file is rewritten
// when something about the machine changes — a few times a minute — and the
// menu bar re-reads it every three seconds. A progress bar that moved three
// times during a copy would be worse than no bar at all: it would look stuck
// for seconds at a time and then jump, which reads as a hang.
//
// This one line is rewritten several times a second and read just as often,
// by a loop that is already running while somebody waits. Keeping it out of
// status.json also means a burst of progress writes cannot interleave with,
// or truncate, the document everything else depends on.

// InstallProgress is how far one install has got.
type InstallProgress struct {
	// Application is what is being installed, so a stale line from a
	// finished install cannot be drawn under the name of a new one.
	Application string
	// Phase is what is happening in words, when the thing doing the work
	// says so. Installer packages do; a file copy does not.
	Phase string
	// Done and Total are bytes, or whatever the two are counted in. Total
	// is 0 when the size is not knowable, which is what tells the menu bar
	// to keep the bar indeterminate rather than invent a number.
	Done, Total int64
	// Percent is 0-100, or -1 when there is nothing honest to show.
	Percent float64
}

// installProgressPath is where the agent writes how far it has got.
func installProgressPath() string {
	return filepath.Join(filepath.Dir(Path()), "install-progress")
}

// PrepareInstallProgress creates the file so the menu bar can read it.
//
// World-READABLE, not world-writable, unlike the request and result files.
// Only the agent ever writes here — the menu bar has nothing to say about
// how far a copy has got — and a file any account could write is a file any
// account could use to put words of its own on somebody's screen.
func PrepareInstallProgress() error {
	path := installProgressPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) // #nosec G302,G304
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o644) // #nosec G302
}

// ReportInstallProgress records how far an install has got.
//
// Best effort and deliberately silent on failure. This is a progress bar: a
// write that does not land costs one frame of animation, and an install must
// never fail because the thing describing it could not be written.
func ReportInstallProgress(p InstallProgress) {
	f, err := os.OpenFile(installProgressPath(), os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304
	if err != nil {
		return
	}
	defer f.Close()

	// Tab-separated on one line, like install-result. A reader that catches
	// a half-written line gets a line it cannot parse and ignores it, which
	// costs one frame; JSON would hand it a decode error for the same
	// price and more code.
	_, _ = fmt.Fprintf(f, "%s\t%s\t%d\t%d\n",
		clean(p.Application), clean(p.Phase), p.Done, p.Total)
}

// ClearInstallProgress says nothing is running, so a finished install's last
// line cannot be drawn against whatever happens next.
func ClearInstallProgress() { _ = os.Truncate(installProgressPath(), 0) }

// ReadInstallProgress returns what the agent last reported, and whether
// there is anything to show.
func ReadInstallProgress() (InstallProgress, bool) {
	data, err := os.ReadFile(installProgressPath()) // #nosec G304 -- the agent's own directory
	if err != nil {
		return InstallProgress{}, false
	}
	line := strings.TrimSpace(string(data))
	if line == "" {
		return InstallProgress{}, false
	}

	parts := strings.Split(line, "\t")
	if len(parts) < 4 {
		// A line caught half-written. One frame, not an error.
		return InstallProgress{}, false
	}

	p := InstallProgress{Application: parts[0], Phase: parts[1], Percent: -1}
	p.Done, _ = strconv.ParseInt(parts[2], 10, 64)
	p.Total, _ = strconv.ParseInt(parts[3], 10, 64)

	// A percentage only where both numbers mean something.
	//
	// Total of 0 is "not knowable" and must stay indeterminate rather than
	// become a division by zero or a bar that sits at 100% from the start.
	if p.Total > 0 {
		p.Percent = float64(p.Done) / float64(p.Total) * 100
		// Clamped, because a copy can report more bytes than the source
		// measured: ditto writes extended attributes and resource forks
		// that a size walk does not count. A bar that overshoots to 112%
		// is a bar nobody believes again.
		if p.Percent > 100 {
			p.Percent = 100
		}
		if p.Percent < 0 {
			p.Percent = 0
		}
	}
	return p, true
}

// clean keeps one record on one line.
func clean(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s))
}
