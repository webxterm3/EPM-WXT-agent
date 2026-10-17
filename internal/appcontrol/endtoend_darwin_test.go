//go:build darwin

package appcontrol

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// The whole path, with nothing stubbed but the inventory: a real application
// bundle, a real process started from it, the real process table read through
// ps, and the real kill.
//
// Every piece of this is unit-tested above. This exists because the pieces
// agreeing in isolation is exactly how enforcement came to be complete and
// inert in the first place — a policy engine that could answer any question
// and a fleet where nothing ever asked it one.
func TestEndToEndABlockedApplicationIsStopped(t *testing.T) {
	dir := t.TempDir()
	// Not inside a .app: from macOS 14 modifying a file in an application
	// bundle needs App Management, which a test binary does not have, and
	// that refusal is a separate thing tested on its own below. What is being
	// proved here is the machinery — policy to decision to lock to kill to
	// restore — so it runs where the filesystem is not in the way.
	bundle := filepath.Join(dir, "Pretend")
	macOS := filepath.Join(bundle, "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(macOS, "Pretend")
	// A real compiled binary, not a script.
	//
	// This matters, and the first version of this test got it wrong twice. A
	// shell script that execs something else is REPLACED by that something
	// else, so the process table reports /bin/sleep and the policy —
	// correctly — evaluates /bin/sleep, which is a protected system path.
	// Matching is on what is actually executing, which is the only thing it
	// can honestly be. A plain copy of /bin/sleep is then killed on launch by
	// the kernel for having a broken signature, so the binary is built here.
	sleeper := buildSleeper(t, binary)

	cmd := exec.Command(sleeper, "120")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the pretend application: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	apps := []appinventory.Application{{
		ID: "pretend", Name: "Pretend", InstallPath: bundle, ExePath: binary,
	}}

	e := New(Options{
		StateDir:  t.TempDir(),
		Policy:    func() *apppolicy.Effective { return blockRule(apppolicy.ModeEnforce, "Pretend") },
		Collector: &fakeCollector{apps: apps},
		// Procs, Killer and Locker are the real ones for this platform.
	})
	e.Reconcile(context.Background())

	// The lock lands on the bundle's binary.
	fi, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0 {
		t.Errorf("the binary is still executable (%04o); it would launch again", fi.Mode().Perm())
	}

	// And the running copy is stopped. Polled rather than asserted once: the
	// sweep signals, the kernel reaps, and those are not the same instant.
	e.sweepProcesses(context.Background())
	if !waitForExit(cmd, 5*time.Second) {
		t.Fatal("the blocked application is still running after a sweep")
	}

	var terminated, locked bool
	for _, ev := range e.Drain() {
		switch ev.Mechanism {
		case MechanismTerminate:
			terminated = true
		case MechanismLock:
			if ev.Outcome == OutcomeApplied {
				locked = true
			}
		}
	}
	if !terminated {
		t.Error("stopping the application was not reported; nobody could find out why it closed")
	}
	if !locked {
		t.Error("preventing the launch was not reported")
	}

	// Withdraw the policy: the application must come back, exactly as it was.
	e.policy = func() *apppolicy.Effective {
		return &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
	}
	e.Reconcile(context.Background())

	fi, err = os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("mode is %04o after the rule was withdrawn, want 0755", got)
	}
}

// waitForExit reports whether the process has gone, polling rather than
// blocking on Wait so the test fails with a message instead of hanging.
func waitForExit(cmd *exec.Cmd, within time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()

	deadline := time.After(within)
	for {
		select {
		case <-done:
			return true
		case <-deadline:
			// Signal 0 asks the kernel whether the process is still there.
			return cmd.Process.Signal(syscall.Signal(0)) != nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// buildSleeper compiles a tiny program that waits, at the given path.
//
// Copying a system binary does not work: macOS kills a copy of a
// platform-signed executable on launch for having a signature that no longer
// matches, so the process is defunct before anything can look at it.
func buildSleeper(t *testing.T, dest string) string {
	t.Helper()

	src := filepath.Join(t.TempDir(), "main.go")
	const program = `package main

import "time"

func main() { time.Sleep(10 * time.Minute) }
`
	if err := os.WriteFile(src, []byte(program), 0o644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", dest, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the pretend application: %v\n%s", err, out)
	}
	return dest
}

// Inside a real .app bundle the lock may be refused by macOS App Management,
// and when it is the agent has to say so in terms somebody can act on.
//
// This is not a failure of the product: the process sweep still closes the
// application. It is the difference between "never opens" and "opens and
// closes", and an operator deciding whether to rely on this needs to be told
// which one they are getting.
func TestBundleLockFailureNamesAppManagement(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "Pretend.app")
	macOS := filepath.Join(bundle, "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(macOS, "Pretend")
	sleepBinary, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, sleepBinary, 0o755); err != nil {
		t.Fatal(err)
	}

	// Launched once first, which is what arms the protection. macOS learns
	// about a bundle when something in it runs, and only then refuses an
	// unprivileged process permission to modify it — so a bundle nobody has
	// ever opened can be locked and the one the user actually uses cannot.
	// Reproducing that order is the whole point of this test.
	launch := exec.Command(binary, "30")
	if err := launch.Start(); err == nil {
		time.Sleep(250 * time.Millisecond)
		_ = launch.Process.Kill()
		_, _ = launch.Process.Wait()
	}

	locker := &darwinLocker{logger: zap.NewNop()}
	err = locker.Lock(Target{Name: "Pretend", Path: bundle, ExePath: binary})
	if err == nil {
		// Granted, or an older macOS. Then the lock simply works, which is
		// the better outcome and nothing to assert about.
		t.Skip("this machine allows the agent to modify application bundles")
	}

	for _, phrase := range []string{"App Management", "System Settings", "closed when it runs"} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("the refusal does not mention %q; it reads as an unexplained chmod error:\n%s",
				phrase, err)
		}
	}
}
