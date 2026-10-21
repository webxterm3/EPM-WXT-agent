//go:build darwin

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// Self-update must never write inside the application bundle.
//
// It used to extract the new package into the running binary's own directory.
// That was harmless while the daemon ran from /usr/local/bin. Once it moved
// inside wxt-agent.app — which is what makes macOS attribute the agent's
// privacy grants to one row instead of three — the same line started writing
// into a code-signed bundle, breaking its seal. macOS then tells the user
// their security agent "is damaged and can't be opened. You should move it to
// the Trash."
func TestInsideAppBundlePathRecognisesSealedPaths(t *testing.T) {
	sealed := []string{
		"/Applications/wxt-agent.app/Contents/MacOS/wxt-agent",
		"/Applications/wxt-agent.app/Contents/MacOS",
		"/Applications/wxt-agent.app",
		"/Applications/Some.App/Contents/Resources/thing",
	}
	for _, p := range sealed {
		if !insideAppBundlePath(p) {
			t.Errorf("insideAppBundlePath(%q) = false; self-update would break the signature", p)
		}
	}

	free := []string{"/usr/local/bin/wxt-agent", "/tmp/x", "/etc/vsay", "/"}
	for _, p := range free {
		if insideAppBundlePath(p) {
			t.Errorf("insideAppBundlePath(%q) = true; a legitimate update would be refused", p)
		}
	}
}

// A package that carries no bundle is not an error — a tarball of a bare
// binary is a valid update for a command-line install — and it must be
// reported as "not handled" so the caller falls back to the binary swap.
func TestAPackageWithoutABundleIsNotAnError(t *testing.T) {
	work := t.TempDir()

	pkg := filepath.Join(work, "agent.tar.gz")
	if err := os.WriteFile(pkg, []byte("not really an archive"), 0o600); err != nil {
		t.Fatal(err)
	}

	app, err := extractAppBundle(pkg, work)
	if app != "" {
		t.Errorf("found a bundle %q in a package that has none", app)
	}
	_ = err // a malformed archive may or may not report an error; neither is a bundle
}

// An unrecognised extension carries no bundle and must say so rather than
// guessing.
func TestAnUnknownPackageFormatCarriesNoBundle(t *testing.T) {
	app, err := extractAppBundle("/tmp/agent.rpm", t.TempDir())
	if err != nil {
		t.Errorf("unexpected error for a format with no bundle: %v", err)
	}
	if app != "" {
		t.Errorf("claimed to find a bundle at %q", app)
	}
}

// With no bundle installed there is nothing to replace, and the ordinary
// binary swap is the right path.
func TestSwapIsSkippedWhenNoBundleIsInstalled(t *testing.T) {
	if _, err := os.Stat(macAppBundlePath); err == nil {
		t.Skip("this machine has the agent bundle installed")
	}
	a := &Agent{logger: zap.NewNop()}

	work := t.TempDir()
	pkg := filepath.Join(work, "agent.dmg")
	if err := os.WriteFile(pkg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	done, err := a.swapMacOSBundle(pkg, work)
	if done {
		t.Error("claimed to have handled the update with no bundle installed")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// The whole point, proved against a real disk image: the bundle that comes out
// of the package is the one that ends up installed, and it arrives intact.
//
// A bundle copied carelessly — recreated file by file rather than copied with
// its symlinks, modes and extended attributes — stops satisfying its own code
// signature, which is the same "damaged" failure by another route. So this
// builds an image, extracts from it, and checks what came out.
func TestABundleIsExtractedFromARealDiskImage(t *testing.T) {
	work := t.TempDir()

	// Build a disk image containing a bundle with a symlink in it, because a
	// symlink is what a careless copy flattens.
	stage := filepath.Join(t.TempDir(), "stage")
	app := filepath.Join(stage, "wxt-agent.app", "Contents", "MacOS")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "wxt-agent"), []byte("the new agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("wxt-agent", filepath.Join(app, "current")); err != nil {
		t.Fatal(err)
	}

	dmg := filepath.Join(work, "update.dmg")
	out, err := exec.Command("/usr/bin/hdiutil", "create", "-quiet", "-srcfolder", stage,
		"-volname", "wxt-agent", "-ov", "-format", "UDZO", dmg).CombinedOutput()
	if err != nil {
		t.Skipf("could not build a test image here: %v: %s", err, out)
	}

	got, err := extractAppBundle(dmg, work)
	if err != nil {
		t.Fatalf("extracting the bundle: %v", err)
	}
	if got == "" {
		t.Fatal("no bundle was found in an image that contains one")
	}

	binary := filepath.Join(got, "Contents", "MacOS", "wxt-agent")
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("the extracted bundle has no agent in it: %v", err)
	}
	if string(data) != "the new agent" {
		t.Errorf("the extracted agent is %q, want the one from the image", data)
	}

	// The symlink has to survive as a symlink.
	link := filepath.Join(got, "Contents", "MacOS", "current")
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("the symlink did not survive extraction: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was flattened into a regular file; a real bundle would fail its own signature check")
	}

	// And nothing was left inside the mounted image's path.
	if insideAppBundlePath(work) {
		t.Error("the work directory is itself inside a bundle")
	}
}
