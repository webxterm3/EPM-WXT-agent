package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The log file and the daemon's captured stdout must not be the same place.
//
// When they were, zap wrote every line into the file and launchd wrote the
// same line again from stdout. The result was a log where every message
// appeared twice — which reads as the agent doing everything twice, and sent
// real debugging down that path before anyone suspected the log itself.
func TestStdoutCollidingWithTheLogFileIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	realStdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = realStdout }()

	if !stdoutGoesTo(path) {
		t.Error("stdout is literally the log file and the collision was not seen — " +
			"every line would be written twice")
	}

	other := filepath.Join(dir, "elsewhere.log")
	if err := os.WriteFile(other, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if stdoutGoesTo(other) {
		t.Error("a different file was reported as the same one, which would drop " +
			"the stdout sink for no reason")
	}
}

// The same file is reachable by more than one name. A string comparison of
// paths would miss a symlink, and the duplication would survive the fix.
func TestACollisionThroughASymlinkIsStillACollision(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "agent.log")
	link := filepath.Join(dir, "linked.log")

	f, err := os.Create(real)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	realStdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = realStdout }()

	if !stdoutGoesTo(link) {
		t.Error("the same file reached by a symlink was not recognised — a path " +
			"comparison would miss this and the log would still double")
	}
}

// A terminal or a pipe is not a file this could be duplicating into, and the
// sink must survive: dropping it would silence `wxt-agent start` run by hand.
func TestAnInteractiveStdoutIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	realStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = realStdout }()

	if stdoutGoesTo(path) {
		t.Error("a pipe was mistaken for the log file — running the agent in a " +
			"terminal would print nothing")
	}
}

func TestNoLogFileMeansNoCollision(t *testing.T) {
	if stdoutGoesTo("") {
		t.Error("an empty path reported a collision")
	}
	if stdoutGoesTo("/nonexistent/nowhere/agent.log") {
		t.Error("a file that does not exist reported a collision")
	}
}

// The plist must not hand launchd the file the agent already writes.
//
// Pinned here because the two constants live in different files and nothing
// stops somebody "tidying" them back into one. The symptom is not a failure —
// it is a log in which every line appears twice, which looks like the agent
// misbehaving rather than the log.
func TestTheDaemonDoesNotCaptureStdoutIntoItsOwnLog(t *testing.T) {
	if macDaemonOutPath == macLogPath {
		t.Fatal("the daemon's StandardOutPath is the agent's own log file, so every " +
			"line lands twice — once written by the logger, once captured by launchd")
	}
	if macDaemonOutPath == "" {
		t.Error("nothing captures the daemon's stdout, so a panic before or after " +
			"the logger exists would leave no trace at all")
	}
}
