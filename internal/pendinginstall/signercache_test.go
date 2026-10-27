//go:build darwin

package pendinginstall

import (
	"os"
	"path/filepath"
	"testing"
)

// A bundle to point the cache at. Its contents do not matter — the real
// verification is stubbed; what is being tested is how often it is asked.
func bundleAt(t *testing.T, dir, name string) string {
	t.Helper()
	bundle := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(bundle, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func stubCodesign(t *testing.T, answer func(string) string) *int {
	t.Helper()
	calls := 0
	original := runCodesign
	runCodesign = func(bundle string) string {
		calls++
		return answer(bundle)
	}
	t.Cleanup(func() {
		runCodesign = original
		signerMu.Lock()
		signerCache = map[signerKey]string{}
		signerMu.Unlock()
	})
	return &calls
}

// codesign --deep --strict reads every file in the bundle. Repeating it on a
// timer, for as long as an image stays mounted, is the agent burning a core
// while somebody waits to install something.
func TestAMountedImageIsVerifiedOnceNotOnEveryScan(t *testing.T) {
	bundle := bundleAt(t, t.TempDir(), "Zoom.app")
	calls := stubCodesign(t, func(string) string { return "Developer ID Application: Zoom" })

	for i := 0; i < 10; i++ {
		if got := verifiedBundleSigner(bundle); got != "Developer ID Application: Zoom" {
			t.Fatalf("scan %d got %q", i, got)
		}
	}
	if *calls != 1 {
		t.Errorf("verified the same mounted bundle %d times, wanted 1", *calls)
	}
}

// A verification that produced nothing is NOT remembered.
//
// Mounting a disk image is not atomic and the scan runs every three seconds,
// so the first look at a volume can land while it is still appearing and get
// no answer. The cache key is the device and inode, which do not change
// while the image stays mounted — so remembering that empty answer made one
// unlucky first scan permanent: properly signed software stayed unverified
// for as long as the image was open, no drag window was opened, and Finder
// asked for an administrator password. Re-opening the image changed nothing,
// because it was the same volume.
//
// It costs almost nothing to ask again: codesign --verify on a bundle with
// no signature returns in about ten milliseconds, measured, because there is
// no signature to walk.
func TestAVerificationThatFailedIsRetriedRatherThanRemembered(t *testing.T) {
	bundle := bundleAt(t, t.TempDir(), "Zoom.app")

	// The first look lands mid-mount and gets nothing; every look after it
	// gets the real answer.
	look := 0
	calls := stubCodesign(t, func(string) string {
		look++
		if look == 1 {
			return ""
		}
		return "Developer ID Application: Zoom"
	})

	if got := verifiedBundleSigner(bundle); got != "" {
		t.Fatalf("first scan got %q, wanted the failure this test is about", got)
	}
	if got := verifiedBundleSigner(bundle); got != "Developer ID Application: Zoom" {
		t.Fatalf("the signer never recovered from one failed check: got %q — the "+
			"application stays unverified and Finder asks for a password", got)
	}
	if *calls != 2 {
		t.Errorf("codesign ran %d times, so the failure was cached", *calls)
	}
}

// /Volumes/Installer is a name macOS hands out again. Keyed on the path
// alone, the second image would inherit the first image's signer — which is
// an unsigned bundle being reported as signed by somebody reputable.
func TestADifferentImageAtTheSamePathIsNotTrustedByInheritance(t *testing.T) {
	dir := t.TempDir()
	first := bundleAt(t, dir, "Installer.app")

	signers := map[string]string{first: "Developer ID Application: Trusted Ltd"}
	calls := stubCodesign(t, func(b string) string { return signers[b] })

	if got := verifiedBundleSigner(first); got != "Developer ID Application: Trusted Ltd" {
		t.Fatalf("first image: got %q", got)
	}

	// Ejected, and something else mounted under the same name.
	if err := os.RemoveAll(first); err != nil {
		t.Fatal(err)
	}
	second := bundleAt(t, dir, "Installer.app")
	delete(signers, second) // whatever this is, it is not signed

	if got := verifiedBundleSigner(second); got != "" {
		t.Errorf("a different image at %s was reported as signed by %q", second, got)
	}
	if *calls != 2 {
		t.Errorf("the replacement image was not verified at all (%d calls)", *calls)
	}
}

// The cache must not grow for the life of the agent — and the scan itself
// has to be what prunes it. Calling forgetUnmountedSigners directly from a
// test would pass just as well with nothing ever calling it in production,
// which is a leak with a green tick next to it.
func TestScanningForgetsImagesThatHaveBeenEjected(t *testing.T) {
	volumes := t.TempDir()
	original := volumesDir
	volumesDir = volumes
	t.Cleanup(func() { volumesDir = original })

	stubCodesign(t, func(string) string { return "Developer ID Application: X" })

	mount := filepath.Join(volumes, "Installer")
	bundleAt(t, mount, "Gone.app")

	if apps := MountedApps(); len(apps) != 1 {
		t.Fatalf("the scan found %d applications, wanted 1", len(apps))
	}
	signerMu.Lock()
	held := len(signerCache)
	signerMu.Unlock()
	if held != 1 {
		t.Fatalf("the scan cached %d signers, wanted 1", held)
	}

	// Ejected.
	if err := os.RemoveAll(mount); err != nil {
		t.Fatal(err)
	}
	MountedApps()

	signerMu.Lock()
	held = len(signerCache)
	signerMu.Unlock()
	if held != 0 {
		t.Errorf("%d entries survived the image being ejected", held)
	}
}
