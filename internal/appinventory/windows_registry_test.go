package appinventory

import (
	"testing"
	"time"
)

func TestApplicationFromRegistry(t *testing.T) {
	app, ok := applicationFromRegistry(RegistryEntry{
		KeyName:         "{AC76BA86-1033-FFFF-7760-BC15014EA700}",
		View:            ViewMachine64,
		DisplayName:     "Adobe Acrobat Reader",
		DisplayVersion:  "23.006.20320",
		Publisher:       "Adobe Inc.",
		InstallLocation: `C:\Program Files\Adobe\Acrobat Reader`,
		InstallDate:     "20260115",
		UninstallString: "MsiExec.exe /X{AC76BA86}",
	})
	if !ok {
		t.Fatal("a normal installed application was rejected")
	}

	if app.Name != "Adobe Acrobat Reader" {
		t.Errorf("Name = %q", app.Name)
	}
	if app.Version != "23.006.20320" {
		t.Errorf("Version = %q", app.Version)
	}
	if app.Publisher != "Adobe Inc." {
		t.Errorf("Publisher = %q", app.Publisher)
	}
	if app.Source != "registry" {
		t.Errorf("Source = %q", app.Source)
	}
	if app.Arch != "x64" {
		t.Errorf("Arch = %q, want x64 for the native registry view", app.Arch)
	}
	want := time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC)
	if !app.InstalledAt.Equal(want) {
		t.Errorf("InstalledAt = %s, want %s", app.InstalledAt, want)
	}
}

// A patched Windows carries hundreds of these. Reporting them would bury the
// applications an operator is actually trying to write policy about.
func TestRegistryDebrisIsRejected(t *testing.T) {
	base := RegistryEntry{KeyName: "k", DisplayName: "Something", View: ViewMachine64}

	cases := map[string]RegistryEntry{
		"no display name":  {KeyName: "k", DisplayName: "   "},
		"system component": withEntry(base, func(e *RegistryEntry) { e.SystemComponent = 1 }),
		"patch of another": withEntry(base, func(e *RegistryEntry) { e.ParentKeyName = "{PARENT}" }),
		"security update":  withEntry(base, func(e *RegistryEntry) { e.ReleaseType = "Security Update" }),
		"update rollup":    withEntry(base, func(e *RegistryEntry) { e.ReleaseType = "Update Rollup" }),
		"hotfix lowercase": withEntry(base, func(e *RegistryEntry) { e.ReleaseType = "hotfix" }),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := applicationFromRegistry(e); ok {
				t.Error("accepted an entry that is not a user-visible application")
			}
		})
	}
}

// The same product registered in both registry views must collapse to one
// record, or every fleet-wide count double-counts it.
func TestSameProductInBothViewsCollapses(t *testing.T) {
	apps := finalise(applicationsFromRegistry([]RegistryEntry{
		{KeyName: "{GUID-1}", View: ViewMachine64, DisplayName: "Zoom", DisplayVersion: "5.17"},
		{KeyName: "{guid-1}", View: ViewMachine32, DisplayName: "Zoom", DisplayVersion: "5.17",
			Publisher: "Zoom Video Communications"},
	}))

	if len(apps) != 1 {
		t.Fatalf("got %d records for one product: %+v", len(apps), apps)
	}
	// The richer of the two duplicates must win, so a sparse entry cannot
	// blank out detail the other one had.
	if apps[0].Publisher != "Zoom Video Communications" {
		t.Errorf("Publisher = %q, want the detail from the fuller duplicate", apps[0].Publisher)
	}
}

func TestParseRegistryInstallDate(t *testing.T) {
	good := map[string]time.Time{
		"20260115":   time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		"2026/01/15": time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		"2026-01-15": time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	}
	for in, want := range good {
		got, ok := parseRegistryInstallDate(in)
		if !ok || !got.Equal(want) {
			t.Errorf("parseRegistryInstallDate(%q) = %s, %v; want %s", in, got, ok, want)
		}
	}

	// A wrong install date is worse than no install date, so anything that
	// cannot be read confidently is reported as absent.
	bad := []string{
		"",
		"   ",
		"not a date",
		"16010101", // the FILETIME epoch — Windows' own "unknown"
		"00000000",
		"20991231", // far future, clearly junk
	}
	for _, in := range bad {
		if _, ok := parseRegistryInstallDate(in); ok {
			t.Errorf("parseRegistryInstallDate(%q) returned a date it should not trust", in)
		}
	}
}

// Display names routinely carry trailing and non-breaking spaces from
// installer templates. Left alone, one product looks like two across machines.
func TestDisplayNameWhitespaceIsNormalised(t *testing.T) {
	a, _ := applicationFromRegistry(RegistryEntry{KeyName: "a", DisplayName: "Google\u00a0Chrome  "})
	b, _ := applicationFromRegistry(RegistryEntry{KeyName: "b", DisplayName: "  Google Chrome"})

	cleanA, _ := normalise(a)
	cleanB, _ := normalise(b)

	if cleanA.Name != "Google Chrome" || cleanB.Name != "Google Chrome" {
		t.Errorf("names did not normalise: %q vs %q", cleanA.Name, cleanB.Name)
	}
}

func withEntry(base RegistryEntry, mutate func(*RegistryEntry)) RegistryEntry {
	out := base
	mutate(&out)
	return out
}

// DisplayIcon is an icon reference, not a path. Taken literally it is useless
// for a path rule; the trailing index and quotes have to come off, and entries
// that point at an icon file rather than a program have to be discarded, or any
// rule written against them matches nothing.
func TestExePathFromDisplayIcon(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"icon index stripped", `C:\Program Files\App\app.exe,0`, `C:\Program Files\App\app.exe`},
		{"quoted with index", `"C:\Program Files\App\app.exe",0`, `C:\Program Files\App\app.exe`},
		{"bare path", `C:\Program Files\App\app.exe`, `C:\Program Files\App\app.exe`},
		{"quoted", `"C:\Program Files\App\app.exe"`, `C:\Program Files\App\app.exe`},

		// An icon file or a resource DLL is not the program, and reporting one
		// as the executable makes every rule written against it match nothing.
		{"icon file rejected", `C:\Program Files\App\icon.ico`, ""},
		{"resource dll rejected", `C:\Windows\System32\shell32.dll,3`, ""},

		// "-123" is not an icon index, so the comma stays part of the path —
		// which then has no .exe on the end and is discarded.
		{"negative suffix is not an index", `C:\App\app.exe,-123`, ""},

		{"empty", "", ""},
		{"blank", "   ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exePathFromDisplayIcon(c.in); got != c.want {
				t.Errorf("exePathFromDisplayIcon(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// A comma is legal in a Windows path, so only a genuine trailing index may be
// stripped.
func TestCommaInPathIsNotMistakenForAnIconIndex(t *testing.T) {
	in := `C:\Program Files\Acme, Inc\app.exe`
	if got := exePathFromDisplayIcon(in); got != in {
		t.Errorf("exePathFromDisplayIcon(%q) = %q, want the path unchanged", in, got)
	}
}

// Per-user installs are how somebody without admin rights installs software —
// the case least-privilege work exists to control. Losing the distinction
// makes the inventory blind to exactly the interesting half.
func TestPerUserInstallKeepsItsScopeAndOwner(t *testing.T) {
	app, ok := applicationFromRegistry(RegistryEntry{
		KeyName:     "Chrome",
		View:        ViewUser,
		DisplayName: "Google Chrome",
		Scope:       ScopeUser,
		OSUser:      `CORP\yesveer`,
	})
	if !ok {
		t.Fatal("rejected")
	}
	if app.Scope != ScopeUser {
		t.Errorf("Scope = %q, want %q", app.Scope, ScopeUser)
	}
	if app.OSUser != `CORP\yesveer` {
		t.Errorf("OSUser = %q", app.OSUser)
	}
}

// Two people on a shared machine can each install Chrome for themselves. Those
// are two installs; keying on the subkey alone would make the second overwrite
// the first, so the machine would report one Chrome and removing it for one
// user would look like it vanished for both.
func TestPerUserInstallsByDifferentUsersDoNotCollide(t *testing.T) {
	apps := finalise(applicationsFromRegistry([]RegistryEntry{
		{KeyName: "Chrome", View: ViewUser, DisplayName: "Google Chrome", Scope: ScopeUser, OSUser: `CORP\yesveer`},
		{KeyName: "Chrome", View: ViewUser, DisplayName: "Google Chrome", Scope: ScopeUser, OSUser: `CORP\amit`},
	}))

	if len(apps) != 2 {
		t.Fatalf("got %d records for two separate per-user installs: %+v", len(apps), apps)
	}
	if apps[0].ID == apps[1].ID {
		t.Errorf("both installs share the id %q", apps[0].ID)
	}
}

// A machine-wide install and a per-user install of the same product are also
// two different things and must not collapse into one.
func TestMachineAndUserInstallsOfTheSameProductStaySeparate(t *testing.T) {
	apps := finalise(applicationsFromRegistry([]RegistryEntry{
		{KeyName: "Chrome", View: ViewMachine64, DisplayName: "Google Chrome", Scope: ScopeMachine},
		{KeyName: "Chrome", View: ViewUser, DisplayName: "Google Chrome", Scope: ScopeUser, OSUser: `CORP\yesveer`},
	}))
	if len(apps) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(apps), apps)
	}
}
