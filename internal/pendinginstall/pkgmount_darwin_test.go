//go:build darwin

package pendinginstall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// mountedImage builds a directory that looks like a mounted disk image.
func mountedImage(t *testing.T, names ...string) string {
	t.Helper()
	vol := t.TempDir()
	for _, n := range names {
		if filepath.Ext(n) == ".app" {
			if err := os.MkdirAll(filepath.Join(vol, n, "Contents"), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(vol, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return vol
}

// stubSigner makes pkgutil answer a fixed way for the length of a test.
func stubSigner(t *testing.T, signer string) {
	t.Helper()
	was := verifiedPackageSigner
	verifiedPackageSigner = func(string) string { return signer }
	t.Cleanup(func() { verifiedPackageSigner = was })
}

func TestAPackageInAnImageIsOfferedByName(t *testing.T) {
	stubSigner(t, "Developer ID Installer: Zoom Video Communications, Inc.")
	vol := mountedImage(t, "Zoom.pkg")

	app, ok := appInVolume(vol)
	if !ok {
		t.Fatal("a disk image holding one package was not recognised")
	}
	if app.Kind != KindPackage {
		t.Errorf("kind = %q, want a package", app.Kind)
	}
	if app.Name != "Zoom" {
		t.Errorf("name = %q, want the file name without its extension", app.Name)
	}
	if app.Publisher == "" {
		t.Error("a signed package reported no publisher")
	}
}

func TestAnUnsignedPackageIsNeverInstallableAndNeverAskable(t *testing.T) {
	stubSigner(t, "")
	vol := mountedImage(t, "Totally Legitimate.pkg")

	app, ok := appInVolume(vol)
	if !ok {
		t.Fatal("the package was not recognised at all")
	}

	// Judged against a policy that allows EVERYTHING by name, which is the
	// dangerous case: the rule says yes and the signature says nothing.
	d := DecideMounted(app, allowByName("Totally Legitimate"))
	if d.Outcome == OutcomeInstallable {
		t.Fatal("an unsigned package was installable — it runs as root")
	}
	if d.Outcome.Requestable() {
		t.Fatal("an unsigned package was offered an approval route; " +
			"no approver can supply a signature")
	}
}

func TestAnUnsignedPackageIsRefusedAtTheMomentItWouldRun(t *testing.T) {
	stubSigner(t, "")
	ran := false
	wasInstall := installPackage
	installPackage = func(string) error { ran = true; return nil }
	t.Cleanup(func() { installPackage = wasInstall })

	err := InstallMounted(MountedApp{
		Kind:       KindPackage,
		Name:       "Totally Legitimate",
		BundlePath: filepath.Join(t.TempDir(), "Totally Legitimate.pkg"),
		// A publisher left over from the earlier decision must not be what
		// is trusted here: the file is re-checked.
		Publisher: "Developer ID Installer: Someone Else",
	})
	if err == nil {
		t.Fatal("an unsigned package was installed")
	}
	if ran {
		t.Fatal("installer was run on an unsigned package")
	}
}

func TestASignedPackageIsRunRatherThanCopied(t *testing.T) {
	stubSigner(t, "Developer ID Installer: Zoom Video Communications, Inc.")
	pkg := filepath.Join(t.TempDir(), "Zoom.pkg")

	got := ""
	wasInstall := installPackage
	installPackage = func(p string) error { got = p; return nil }
	t.Cleanup(func() { installPackage = wasInstall })

	wasCopy := copyTree
	copyTree = func(_ context.Context, _, _ string) error {
		t.Fatal("a package was copied into /Applications instead of being run")
		return nil
	}
	t.Cleanup(func() { copyTree = wasCopy })

	if err := InstallMounted(MountedApp{
		Kind: KindPackage, Name: "Zoom", BundlePath: pkg,
	}); err != nil {
		t.Fatalf("installing a signed package: %v", err)
	}
	if got != pkg {
		t.Errorf("installer ran against %q, want %q", got, pkg)
	}
}

func TestAnImageHoldingBothAPackageAndAnApplicationIsNotGuessedAt(t *testing.T) {
	stubSigner(t, "Developer ID Installer: Someone")
	vol := mountedImage(t, "Thing.app", "Thing.pkg")

	if _, ok := appInVolume(vol); ok {
		t.Fatal("an image holding both was resolved to one of them; " +
			"which one the person meant is a guess")
	}
}

func TestTwoPackagesInOneImageAreNotGuessedAt(t *testing.T) {
	stubSigner(t, "Developer ID Installer: Someone")
	vol := mountedImage(t, "One.pkg", "Two.pkg")

	if _, ok := appInVolume(vol); ok {
		t.Fatal("an image holding two packages was resolved to one of them")
	}
}
