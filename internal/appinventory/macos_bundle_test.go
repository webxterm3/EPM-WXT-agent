package appinventory

import (
	"encoding/json"
	"testing"
)

// Shaped like real `plutil -convert json -o - Info.plist` output, including
// the many keys we ignore.
const chromePlistJSON = `{
  "CFBundleDevelopmentRegion": "en",
  "CFBundleDisplayName": "Google Chrome",
  "CFBundleExecutable": "Google Chrome",
  "CFBundleIdentifier": "com.google.Chrome",
  "CFBundleName": "Chrome",
  "CFBundlePackageType": "APPL",
  "CFBundleShortVersionString": "120.0.6099.109",
  "CFBundleVersion": "6099.109",
  "LSMinimumSystemVersion": "11.0"
}`

// Real codesign output: leaf certificate first, then the chain.
const chromeCodesign = `Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
Identifier=com.google.Chrome
Format=app bundle with Mach-O universal (x86_64 arm64)
Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=15 Jan 2026 at 10:03:01
`

func mustPlist(t *testing.T, raw string) bundleInfo {
	t.Helper()
	var info bundleInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		t.Fatalf("decode plist: %v", err)
	}
	return info
}

func TestApplicationFromBundle(t *testing.T) {
	info := mustPlist(t, chromePlistJSON)
	authority := parseCodesignAuthority(chromeCodesign)

	app, ok := applicationFromBundle("/Applications/Google Chrome.app", info, authority)
	if !ok {
		t.Fatal("a normal application bundle was rejected")
	}

	// CFBundleDisplayName is what Finder shows; CFBundleName here is the
	// abbreviated "Chrome", which is not what an operator would search for.
	if app.Name != "Google Chrome" {
		t.Errorf("Name = %q, want the display name", app.Name)
	}
	if app.BundleID != "com.google.Chrome" {
		t.Errorf("BundleID = %q", app.BundleID)
	}
	if app.ID != "bundle:com.google.chrome" {
		t.Errorf("ID = %q, want the bundle id to be the stable identity", app.ID)
	}
	if app.Version != "120.0.6099.109" {
		t.Errorf("Version = %q, want the short version string", app.Version)
	}
	if app.Publisher != "Developer ID Application: Google LLC (EQHXZ8M8AV)" {
		t.Errorf("Publisher = %q", app.Publisher)
	}
	if app.Source != SourceBundle {
		t.Errorf("Source = %q", app.Source)
	}
}

// Blocking an OS-supplied application is how a machine becomes unusable, so
// those must be distinguishable from software somebody installed.
func TestSystemApplicationsAreMarked(t *testing.T) {
	info := mustPlist(t, `{"CFBundleIdentifier":"com.apple.Terminal","CFBundleName":"Terminal","CFBundlePackageType":"APPL"}`)

	app, ok := applicationFromBundle("/System/Applications/Utilities/Terminal.app", info, "Software Signing")
	if !ok {
		t.Fatal("a system application was rejected")
	}
	if app.Source != SourceSystemBundle {
		t.Errorf("Source = %q, want %q", app.Source, SourceSystemBundle)
	}
}

// Frameworks and plug-ins live inside application directories but are not
// things anybody installs or writes policy about.
func TestNonApplicationBundlesAreRejected(t *testing.T) {
	for _, pkgType := range []string{"FMWK", "BNDL", "XPC!"} {
		info := bundleInfo{CFBundleIdentifier: "com.example.thing", CFBundleName: "Thing", CFBundlePackageType: pkgType}
		if _, ok := applicationFromBundle("/Applications/Thing.app", info, ""); ok {
			t.Errorf("accepted a bundle of type %q", pkgType)
		}
	}
}

// Plenty of bundles omit CFBundlePackageType entirely; rejecting those would
// silently lose real applications.
func TestBundleWithNoPackageTypeIsAccepted(t *testing.T) {
	info := bundleInfo{CFBundleIdentifier: "com.example.app", CFBundleName: "Example"}
	if _, ok := applicationFromBundle("/Applications/Example.app", info, ""); !ok {
		t.Error("rejected a bundle that merely omits CFBundlePackageType")
	}
}

// The name recorded has to be the name somebody would type into a policy
// rule, which is the name the Finder shows — the bundle's folder name — not
// CFBundleName.
//
// CFBundleName is a short internal name; Apple's guidance caps it around 16
// characters. Visual Studio Code sets it to "Code". Recording that meant an
// operator who looked at their Applications folder, wrote a rule for "Visual
// Studio Code" and saved it got a rule that matched nothing, with no error
// anywhere — the policy was right, the engine was right, and the product did
// nothing.
func TestBundleNameIsWhatSomebodyWouldType(t *testing.T) {
	cases := []struct {
		name string
		path string
		info bundleInfo
		want string
	}{
		{
			// The real case, with Visual Studio Code's real plist: it sets
			// BOTH plist name fields to "Code", and the Finder still shows
			// "Visual Studio Code". Neither plist field can be trusted here.
			"the folder name beats both plist names",
			"/Applications/Visual Studio Code.app",
			bundleInfo{CFBundleDisplayName: "Code", CFBundleName: "Code"},
			"Visual Studio Code",
		},
		{
			"the display name is the fallback",
			"/Applications/.app",
			bundleInfo{CFBundleDisplayName: "Some App", CFBundleName: "SA"},
			"Some App",
		},
		{
			"the short bundle name is the last resort",
			"/Applications/.app",
			bundleInfo{CFBundleName: "Code"},
			"Code",
		},
		{
			"nothing but a folder name",
			"/Applications/Some App.app",
			bundleInfo{},
			"Some App",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, ok := applicationFromBundle(c.path, c.info, "")
			if !ok {
				t.Fatal("rejected")
			}
			if app.Name != c.want {
				t.Errorf("Name = %q, want %q", app.Name, c.want)
			}
		})
	}
}

// Without a bundle id there is nothing stable to reconcile against, so the
// path has to stand in — otherwise the app looks reinstalled on every scan.
func TestBundleWithoutAnIdentifierUsesItsPath(t *testing.T) {
	app, ok := applicationFromBundle("/Applications/Legacy.app", bundleInfo{CFBundleName: "Legacy"}, "")
	if !ok {
		t.Fatal("rejected")
	}
	if app.ID != "path:/Applications/Legacy.app" {
		t.Errorf("ID = %q", app.ID)
	}
}

func TestParseCodesignAuthority(t *testing.T) {
	// The first Authority line is the signer; the ones after it are the
	// intermediate and root CAs, which identify nobody.
	if got := parseCodesignAuthority(chromeCodesign); got != "Developer ID Application: Google LLC (EQHXZ8M8AV)" {
		t.Errorf("got %q", got)
	}

	appleSigned := "Identifier=com.apple.Terminal\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\n"
	if got := parseCodesignAuthority(appleSigned); got != "Software Signing" {
		t.Errorf("got %q", got)
	}

	// Unsigned, or codesign failed — best-effort, so no publisher rather than
	// a wrong one.
	unsigned := "/Applications/Thing.app: code object is not signed at all\n"
	if got := parseCodesignAuthority(unsigned); got != "" {
		t.Errorf("got %q for an unsigned bundle, want empty", got)
	}
	if got := parseCodesignAuthority(""); got != "" {
		t.Errorf("got %q for empty output", got)
	}
}

// A path rule has to match what actually runs, which on macOS is never the
// .app directory — it is the binary under Contents/MacOS.
func TestBundleExecutablePath(t *testing.T) {
	info := mustPlist(t, chromePlistJSON)
	app, ok := applicationFromBundle("/Applications/Google Chrome.app", info, "")
	if !ok {
		t.Fatal("rejected")
	}
	want := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if app.ExePath != want {
		t.Errorf("ExePath = %q, want %q", app.ExePath, want)
	}
}

// Guessing an executable name would produce a path that matches nothing, which
// is worse than admitting there isn't one.
func TestBundleWithNoDeclaredExecutableHasNoExePath(t *testing.T) {
	app, ok := applicationFromBundle("/Applications/Thing.app",
		bundleInfo{CFBundleIdentifier: "com.example.thing", CFBundleName: "Thing"}, "")
	if !ok {
		t.Fatal("rejected")
	}
	if app.ExePath != "" {
		t.Errorf("ExePath = %q, want empty", app.ExePath)
	}
}

// Software in a home directory is software installed without admin rights —
// exactly what least-privilege work exists to control.
func TestHomeDirectoryApplicationsAreUserScoped(t *testing.T) {
	info := mustPlist(t, chromePlistJSON)

	user, _ := applicationFromBundle("/Users/yesveer/Applications/Google Chrome.app", info, "")
	if user.Scope != ScopeUser {
		t.Errorf("Scope = %q, want %q", user.Scope, ScopeUser)
	}
	if user.OSUser != "yesveer" {
		t.Errorf("OSUser = %q, want yesveer", user.OSUser)
	}

	machine, _ := applicationFromBundle("/Applications/Google Chrome.app", info, "")
	if machine.Scope != ScopeMachine {
		t.Errorf("Scope = %q, want %q", machine.Scope, ScopeMachine)
	}
	if machine.OSUser != "" {
		t.Errorf("OSUser = %q, want empty for a machine-wide install", machine.OSUser)
	}

	// /Users/Shared belongs to nobody in particular.
	shared, _ := applicationFromBundle("/Users/Shared/Google Chrome.app", info, "")
	if shared.Scope != ScopeMachine {
		t.Errorf("/Users/Shared Scope = %q, want %q", shared.Scope, ScopeMachine)
	}
}

// Two people can each keep the same app in their own ~/Applications. Those are
// two installs, and the bundle id alone would collapse them into one.
func TestSameBundleInTwoHomeDirectoriesDoesNotCollide(t *testing.T) {
	info := mustPlist(t, chromePlistJSON)

	apps := finalise([]Application{
		must(applicationFromBundle("/Users/yesveer/Applications/Google Chrome.app", info, "")),
		must(applicationFromBundle("/Users/amit/Applications/Google Chrome.app", info, "")),
		must(applicationFromBundle("/Applications/Google Chrome.app", info, "")),
	})

	if len(apps) != 3 {
		t.Fatalf("got %d records for three separate installs: %+v", len(apps), apps)
	}
	seen := map[string]bool{}
	for _, a := range apps {
		if seen[a.ID] {
			t.Errorf("duplicate id %q", a.ID)
		}
		seen[a.ID] = true
	}
}

func must(app Application, ok bool) Application {
	if !ok {
		panic("applicationFromBundle rejected a fixture it should accept")
	}
	return app
}

// A policy rule is written by somebody looking at their Applications folder,
// so the name recorded has to be the one shown there. This pins the specific
// regression: reading CFBundleName made Visual Studio Code report "Code", and
// a correct rule for "Visual Studio Code" matched nothing with no error
// anywhere — the policy was right, the engine was right, and nothing happened.
func TestTheFolderNameIsNotOverriddenByThePlist(t *testing.T) {
	// Exactly what Visual Studio Code ships.
	app, ok := applicationFromBundle(
		"/Applications/Visual Studio Code.app",
		bundleInfo{
			CFBundleIdentifier:  "com.microsoft.VSCode",
			CFBundleName:        "Code",
			CFBundleDisplayName: "Code",
		}, "")
	if !ok {
		t.Fatal("rejected")
	}
	if app.Name != "Visual Studio Code" {
		t.Fatalf("Name = %q, want %q — a rule written against the Finder's name would not match",
			app.Name, "Visual Studio Code")
	}
}
