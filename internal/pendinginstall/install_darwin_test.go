//go:build darwin

package pendinginstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// intoTempApplications points the installer at a directory a test owns.
func intoTempApplications(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	original := applicationsDir
	applicationsDir = dir
	t.Cleanup(func() { applicationsDir = original })
	return dir
}

// makeBundle builds a minimal .app with a marker inside it.
func makeBundle(t *testing.T, dir, name, marker string) string {
	t.Helper()
	bundle := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(bundle, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "Contents", "version"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func markerOf(t *testing.T, bundle string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(bundle, "Contents", "version"))
	if err != nil {
		t.Fatalf("reading %s: %v", bundle, err)
	}
	return string(b)
}

// The agent does the copy because the person cannot: a managed Mac refuses
// to let an access-control entry be written on /Applications even for root,
// so the drag the original design relied on meets the administrator password
// sheet instead.
func TestApprovedSoftwareIsInstalledByTheAgent(t *testing.T) {
	apps := intoTempApplications(t)
	src := makeBundle(t, t.TempDir(), "Claude.app", "1.0")

	if err := InstallBundle(src); err != nil {
		t.Fatalf("could not install: %v", err)
	}
	if got := markerOf(t, filepath.Join(apps, "Claude.app")); got != "1.0" {
		t.Errorf("installed version %q", got)
	}
}

// An upgrade replaces what is there. This is the case the drag could never
// do at all, because replacing needs the old bundle deleted.
func TestAnUpgradeReplacesTheInstalledCopy(t *testing.T) {
	apps := intoTempApplications(t)
	makeBundle(t, apps, "Claude.app", "1.0")
	src := makeBundle(t, t.TempDir(), "Claude.app", "2.0")

	if err := InstallBundle(src); err != nil {
		t.Fatalf("could not upgrade: %v", err)
	}
	if got := markerOf(t, filepath.Join(apps, "Claude.app")); got != "2.0" {
		t.Errorf("after upgrading, version is %q", got)
	}
}

// A copy that dies HALF WAY must leave the working copy alone.
//
// This is what the staging directory is for, and the case that matters: a
// disk filling up or an image being ejected mid-copy. Replacing somebody's
// working application with a partial one is worse than not upgrading it,
// and a partial .app does not launch at all.
func TestACopyThatFailsHalfWayLeavesTheWorkingCopyInPlace(t *testing.T) {
	apps := intoTempApplications(t)
	makeBundle(t, apps, "Claude.app", "1.0")
	src := makeBundle(t, t.TempDir(), "Claude.app", "2.0")

	original := copyTree
	copyTree = func(ctx context.Context, from, to string) error {
		// Half a bundle written, then the copy dies.
		if err := os.MkdirAll(filepath.Join(to, "Contents"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, "Contents", "version"), []byte("partial"), 0o644); err != nil {
			return err
		}
		return errors.New("no space left on device")
	}
	t.Cleanup(func() { copyTree = original })

	if err := InstallBundle(src); err == nil {
		t.Fatal("a copy that died half way reported success")
	}
	if got := markerOf(t, filepath.Join(apps, "Claude.app")); got != "1.0" {
		t.Fatalf("the working copy was replaced with %q", got)
	}
}

// And a source that is simply not there fails before anything is touched.
func TestInstallingSomethingThatIsNotThereChangesNothing(t *testing.T) {
	apps := intoTempApplications(t)
	makeBundle(t, apps, "Claude.app", "1.0")

	if err := InstallBundle(filepath.Join(t.TempDir(), "Claude.app")); err == nil {
		t.Fatal("installing something that does not exist reported success")
	}
	if got := markerOf(t, filepath.Join(apps, "Claude.app")); got != "1.0" {
		t.Errorf("the installed copy is now %q", got)
	}
}

// Nothing is left behind for somebody to find in their Applications folder.
func TestNoStagingDirectoryIsLeftBehind(t *testing.T) {
	apps := intoTempApplications(t)
	src := makeBundle(t, t.TempDir(), "Claude.app", "1.0")

	_ = InstallBundle(src)
	_ = InstallBundle(filepath.Join(t.TempDir(), "Missing.app"))

	entries, err := os.ReadDir(apps)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".app" {
			t.Errorf("left %s in the Applications folder", e.Name())
		}
	}
}

// The agent replaces itself through its own update path, which stops and
// restarts the service around the swap. Copying over a running agent from
// here would replace the binary underneath the process doing the copying.
func TestTheAgentDoesNotInstallOverItself(t *testing.T) {
	intoTempApplications(t)
	src := makeBundle(t, t.TempDir(), "wxt-agent.app", "9.9")

	original := applicationsDir
	applicationsDir = "/Applications"
	defer func() { applicationsDir = original }()

	err := InstallBundle(src)
	if err == nil {
		t.Fatal("the agent agreed to install over its own running copy")
	}
	// The REASON matters. Without the guard this still fails — because a
	// test cannot write to the real /Applications — and a test that accepts
	// any error would pass with the guard deleted.
	if !strings.Contains(err.Error(), "own update") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
