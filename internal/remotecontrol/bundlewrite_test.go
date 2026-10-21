package remotecontrol

import (
	"os"
	"path/filepath"
	"testing"
)

// An application bundle is sealed by its code signature. Writing one byte
// inside it breaks that seal, and macOS then tells the user their security
// agent "is damaged and can't be opened" and offers to move it to the Trash.
//
// That is what happened: the helper shipped in the bundle and the helper
// embedded in the agent are both correct and both signed, but codesign is not
// deterministic — signing identical input twice produces different bytes — so
// the byte comparison in Extract always reported a difference and always
// rewrote the bundle copy on the first session.
func TestEnsureHelperNeverWritesIntoAnAppBundle(t *testing.T) {
	root := t.TempDir()
	macOS := filepath.Join(root, "wxt-agent.app", "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}

	helper := filepath.Join(macOS, CanonicalHelperName())
	const sentinel = "the copy that shipped in the signed bundle"
	if err := os.WriteFile(helper, []byte(sentinel), 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(helper)
	if err != nil {
		t.Fatal(err)
	}

	// Stand in an embedded helper, so the extract path this guard protects is
	// actually reached. A test binary carries none, and without this the test
	// passes whether or not the guard exists.
	withEmbeddedHelper(t, []byte("a freshly signed copy, different byte for byte"))

	got, err := EnsureHelper(macOS)
	if err != nil {
		t.Fatalf("EnsureHelper: %v", err)
	}
	if got != helper {
		t.Errorf("EnsureHelper returned %q, want the bundle's own copy %q", got, helper)
	}

	after, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != sentinel {
		t.Fatal("the bundle's helper was overwritten — the application's signature is now broken " +
			"and macOS will report it as damaged")
	}
	nowStat, err := os.Stat(helper)
	if err != nil {
		t.Fatal(err)
	}
	if !nowStat.ModTime().Equal(before.ModTime()) {
		t.Error("the bundle's helper was rewritten with identical content; the seal is still broken")
	}
}

func TestInsideAppBundleRecognisesTheSealedPaths(t *testing.T) {
	inside := []string{
		"/Applications/wxt-agent.app/Contents/MacOS",
		"/Applications/wxt-agent.app/Contents/Resources/anything",
		"/Applications/Some.App/Contents/MacOS",
		"/Applications/wxt-agent.app",
	}
	for _, p := range inside {
		if !insideAppBundle(p) {
			t.Errorf("insideAppBundle(%q) = false; the agent would write into a signed bundle", p)
		}
	}

	outside := []string{
		"/usr/local/bin",
		"/etc/vsay",
		"/Users/someone/Downloads",
		"/",
	}
	for _, p := range outside {
		if insideAppBundle(p) {
			t.Errorf("insideAppBundle(%q) = true; the agent would refuse to install a helper it needs", p)
		}
	}
}

// With no helper in the bundle the agent must still work — it installs one
// somewhere writable rather than refusing to start a session.
func TestAnEmptyBundleFallsBackToAWritableDirectory(t *testing.T) {
	root := t.TempDir()
	macOS := filepath.Join(root, "wxt-agent.app", "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}

	withEmbeddedHelper(t, []byte("an embedded helper"))

	got, err := EnsureHelper(macOS)
	if err == nil && insideAppBundle(got) {
		t.Fatalf("fell back to %q, which is still inside the bundle", got)
	}
	// Either it installed elsewhere or it reported that it could not. Both are
	// acceptable; writing into the bundle is not.
	if err == nil && got != "" {
		if _, statErr := os.Stat(filepath.Join(macOS, CanonicalHelperName())); statErr == nil {
			t.Error("a helper was written into the bundle after all")
		}
	}
}

// withEmbeddedHelper makes the agent behave as though it carries an embedded
// helper, and restores the real functions afterwards.
func withEmbeddedHelper(t *testing.T, content []byte) {
	t.Helper()
	oldAvailable, oldExtract := helperAvailable, helperExtract

	helperAvailable = func() bool { return true }
	helperExtract = func(path string) (string, error) {
		if err := os.WriteFile(path, content, 0o755); err != nil { // #nosec G306 -- a test fixture
			return "", err
		}
		return path, nil
	}

	t.Cleanup(func() {
		helperAvailable, helperExtract = oldAvailable, oldExtract
	})
}
