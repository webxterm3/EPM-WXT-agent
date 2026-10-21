package main

import (
	"os"
)

// Where the agent's log lines go, and the one way they end up doubled.
//
// zap writes to the log file directly AND to stdout. Under launchd, the
// daemon's StandardOutPath used to be that same file, so every line arrived
// twice — once written, once captured — and the log read as though the agent
// were doing everything two times. It was not; the log was.
//
// Pointing the daemon's stdout elsewhere fixes new installs, but every machine
// already enrolled carries the old plist until somebody re-runs configure. So
// the agent detects the collision itself and drops the redundant sink, which
// repairs those machines on their next restart with nothing to do by hand.

// stdoutGoesTo reports whether this process's stdout is already the file at
// path.
//
// Compared by identity, not by name: launchd is handed a path, but what the
// process receives is an open descriptor, and the same file is reachable
// through a symlink, a bind mount or a relative path that no string comparison
// would match. os.SameFile compares the device and inode underneath.
func stdoutGoesTo(path string) bool {
	if path == "" {
		return false
	}
	out, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	// A terminal or a pipe is not a file we could be duplicating into.
	if !out.Mode().IsRegular() {
		return false
	}
	target, err := os.Stat(path)
	if err != nil {
		return false
	}
	return os.SameFile(out, target)
}
