//go:build darwin

package pendinginstall

import (
	"os"
	"path/filepath"
	"testing"
)

func installedBundle(t *testing.T, dir, name, bundleID string) string {
	t.Helper()
	bundle := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(bundle, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(bundle, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func clearIdentityCache(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		installedMu.Lock()
		installedCache = map[signerKey]Identity{}
		installedMu.Unlock()
	})
}

// Policy is written against four things. The removal pass was judging
// installed software on two of them and leaving the other two empty, and the
// matcher fails any rule that constrains a field it is not given — so a rule
// allowing everything signed by Microsoft granted nobody permission to
// remove anything.
func TestAnInstalledApplicationIsIdentifiedByMoreThanItsFolderName(t *testing.T) {
	clearIdentityCache(t)
	stubCodesign(t, func(string) string { return "Developer ID Application: Microsoft Corporation" })

	bundle := installedBundle(t, t.TempDir(), "Visual Studio Code.app", "com.microsoft.VSCode")
	id := InstalledIdentity(bundle)

	if id.Name != "Visual Studio Code" {
		t.Errorf("name %q", id.Name)
	}
	if id.BundleID != "com.microsoft.VSCode" {
		t.Errorf("bundle id %q — a bundle-id rule can never match", id.BundleID)
	}
	if id.Publisher != "Developer ID Application: Microsoft Corporation" {
		t.Errorf("publisher %q — a publisher rule can never match", id.Publisher)
	}
}

// A hundred applications, every three seconds, is not a question worth
// asking twice.
//
// Measured by taking the Info.plist away after the first read: a cached
// answer survives it, a re-read comes back empty. Counting codesign calls
// would not test this at all — the signer has a cache of its own, so it
// would answer once whether or not this one existed.
func TestAnInstalledApplicationIsReadOnceNotOnEveryScan(t *testing.T) {
	clearIdentityCache(t)
	stubCodesign(t, func(string) string { return "Developer ID Application: Microsoft Corporation" })

	bundle := installedBundle(t, t.TempDir(), "Visual Studio Code.app", "com.microsoft.VSCode")
	if got := InstalledIdentity(bundle).BundleID; got != "com.microsoft.VSCode" {
		t.Fatalf("first read got %q", got)
	}

	if err := os.Remove(filepath.Join(bundle, "Contents", "Info.plist")); err != nil {
		t.Fatal(err)
	}
	if got := InstalledIdentity(bundle).BundleID; got != "com.microsoft.VSCode" {
		t.Errorf("the identity was read again rather than remembered (%q) — a "+
			"hundred applications would mean a hundred Info.plist reads and "+
			"signature checks every three seconds", got)
	}
}

// A read that failed once must not become the permanent truth about an
// application — the same rule the signer cache follows.
func TestAFailedReadIsNotRememberedAsTheAnswer(t *testing.T) {
	clearIdentityCache(t)
	look := 0
	stubCodesign(t, func(string) string {
		look++
		if look == 1 {
			return ""
		}
		return "Developer ID Application: Microsoft Corporation"
	})

	bundle := installedBundle(t, t.TempDir(), "Visual Studio Code.app", "com.microsoft.VSCode")
	if got := InstalledIdentity(bundle).Publisher; got != "" {
		t.Fatalf("first read got %q, wanted the failure this test is about", got)
	}
	if got := InstalledIdentity(bundle).Publisher; got == "" {
		t.Error("an application whose signature could not be read once is " +
			"treated as unsigned for ever, so no publisher rule will ever " +
			"grant anything for it")
	}
}

// Uninstalled applications are forgotten, so the cache does not grow for the
// life of the agent.
func TestUninstalledApplicationsAreForgotten(t *testing.T) {
	clearIdentityCache(t)
	stubCodesign(t, func(string) string { return "Developer ID Application: Microsoft Corporation" })

	bundle := installedBundle(t, t.TempDir(), "Gone.app", "com.example.Gone")
	InstalledIdentity(bundle)

	installedMu.Lock()
	held := len(installedCache)
	installedMu.Unlock()
	if held != 1 {
		t.Fatalf("nothing was cached (%d entries)", held)
	}

	ForgetUninstalledIdentities(nil)

	installedMu.Lock()
	held = len(installedCache)
	installedMu.Unlock()
	if held != 0 {
		t.Errorf("%d entries survived every application being uninstalled", held)
	}
}
