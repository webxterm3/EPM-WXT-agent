//go:build darwin

package appcontrol

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// The macOS process table is read with ps because comm there is the full
// executable path — which is what a policy matches on, and what neither /proc
// (absent) nor a cgo-free gopsutil reliably gives.
func TestParsePSKeepsPathsWithSpaces(t *testing.T) {
	const out = `    1     0 /sbin/launchd
 2208 73574 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  530     1 /System/Library/Frameworks/CoreServices.framework/Versions/A/Support/fseventsd
`
	procs := parsePS(out)
	if len(procs) != 3 {
		t.Fatalf("parsed %d processes, want 3", len(procs))
	}
	if procs[1].PID != 2208 || procs[1].PPID != 73574 {
		t.Errorf("pid/ppid = %d/%d, want 2208/73574", procs[1].PID, procs[1].PPID)
	}
	const want = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if procs[1].ExePath != want {
		t.Errorf("ExePath = %q, want %q — splitting on every space shreds macOS paths", procs[1].ExePath, want)
	}
}

func TestReadingTheRealProcessTable(t *testing.T) {
	procs, err := darwinProcs{}.List(context.Background())
	if err != nil {
		t.Fatalf("listing processes: %v", err)
	}
	if len(procs) < 10 {
		t.Fatalf("found %d processes on a running Mac", len(procs))
	}
	var withPaths int
	for _, p := range procs {
		if filepath.IsAbs(p.ExePath) {
			withPaths++
		}
	}
	if withPaths < len(procs)/2 {
		t.Errorf("only %d of %d processes have an absolute path; policy could not match them",
			withPaths, len(procs))
	}
}

// Locking must be reversible down to the original mode, because the
// alternative is software this product broke and did not put back.
func TestExecuteBitLockIsReversible(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "Pretend.app")
	macOS := filepath.Join(bundle, "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(macOS, "Pretend")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	locker := &darwinLocker{logger: zap.NewNop()}
	target := Target{Name: "Pretend", Path: bundle, ExePath: binary}

	if err := locker.Lock(target); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	fi, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0 {
		t.Fatalf("mode is %04o after locking; the application would still launch", fi.Mode().Perm())
	}

	// Lock runs on every reconcile pass; a second one must not change anything.
	if err := locker.Lock(target); err != nil {
		t.Fatalf("second Lock: %v", err)
	}

	if err := locker.Unlock(target); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fi, err = os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("mode is %04o after restoring, want 0755", got)
	}
}

// Restoring must not widen a binary that was deliberately owner-only.
func TestUnlockDoesNotWidenPermissions(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "private-tool")
	if err := os.WriteFile(binary, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	locker := &darwinLocker{logger: zap.NewNop()}
	target := Target{Name: "private-tool", Path: binary, ExePath: binary}

	if err := locker.Lock(target); err != nil {
		t.Fatal(err)
	}
	if err := locker.Unlock(target); err != nil {
		t.Fatal(err)
	}
	if got := (mustStat(t, binary)); got != 0o700 {
		t.Errorf("mode is %04o after restoring, want 0700 — unlocking must not grant access nobody had", got)
	}
}

// An application uninstalled while it was locked has nothing to restore.
// Reporting that as an error would keep the record forever and retry it on
// every pass.
func TestUnlockingSomethingAlreadyGoneSucceeds(t *testing.T) {
	locker := &darwinLocker{logger: zap.NewNop()}
	err := locker.Unlock(Target{
		Name: "Gone", Path: "/Applications/Gone.app",
		ExePath: "/Applications/Gone.app/Contents/MacOS/Gone",
	})
	if err != nil {
		t.Errorf("Unlock of a removed application returned %v", err)
	}
}

func mustStat(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
