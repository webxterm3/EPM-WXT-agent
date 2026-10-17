package appinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Homebrew --------------------------------------------------------------

// writeCellar lays out one formula the way Homebrew does.
func writeCellar(t *testing.T, prefix, name, version string, onRequest bool) string {
	t.Helper()
	dir := filepath.Join(prefix, "Cellar", name, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	receipt := `{"installed_on_request":` + boolText(onRequest) + `,"time":1700000000,"arch":"arm64"}`
	if err := os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(receipt), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func collect(t *testing.T, c Collector) map[string]Application {
	t.Helper()
	apps, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	out := make(map[string]Application, len(apps))
	for _, a := range apps {
		out[a.Name] = a
	}
	return out
}

// Formulae are the whole reason this collector exists: they install no bundle,
// write no registry key and appear in no Applications folder, so to every
// other collector the software a developer runs all day is invisible.
func TestHomebrewReportsFormulae(t *testing.T) {
	prefix := t.TempDir()
	writeCellar(t, prefix, "kubectl", "1.31.0", true)

	apps := collect(t, &HomebrewCollector{Prefixes: []string{prefix}})

	app, ok := apps["kubectl"]
	if !ok {
		t.Fatalf("kubectl is missing; got %v", apps)
	}
	if app.Version != "1.31.0" {
		t.Errorf("Version = %q, want 1.31.0", app.Version)
	}
	if app.Publisher != HomebrewPublisher {
		t.Errorf("Publisher = %q, want %q — 'block everything from Homebrew' has to be one rule",
			app.Publisher, HomebrewPublisher)
	}
	if app.Source != SourceHomebrew {
		t.Errorf("Source = %q, want %q", app.Source, SourceHomebrew)
	}
	if app.InstalledAt.IsZero() {
		t.Error("the install time from the receipt was not read")
	}
}

// A machine with twenty packages somebody chose has eighty more behind them.
// Listing all hundred identically buries the twenty anybody decided about.
func TestHomebrewLabelsDependencies(t *testing.T) {
	prefix := t.TempDir()
	writeCellar(t, prefix, "node", "22.0.0", true)
	writeCellar(t, prefix, "icu4c", "74.2", false)

	apps := collect(t, &HomebrewCollector{Prefixes: []string{prefix}})

	if apps["node"].Source != SourceHomebrew {
		t.Errorf("node Source = %q, want %q", apps["node"].Source, SourceHomebrew)
	}
	if apps["icu4c"].Source != SourceHomebrewDep {
		t.Errorf("icu4c Source = %q, want %q", apps["icu4c"].Source, SourceHomebrewDep)
	}
	// Labelled, not hidden: an inventory with holes is worse than a long one.
	if _, ok := apps["icu4c"]; !ok {
		t.Error("a dependency was dropped from the inventory entirely")
	}
}

// Blocking a formula means acting on the binary that actually runs, which is
// the symlink in <prefix>/bin and not the Cellar directory.
func TestHomebrewFindsTheExecutable(t *testing.T) {
	prefix := t.TempDir()
	writeCellar(t, prefix, "kubectl", "1.31.0", true)

	bin := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	apps := collect(t, &HomebrewCollector{Prefixes: []string{prefix}})
	want := filepath.Join(bin, "kubectl")
	if got := apps["kubectl"].ExePath; got != want {
		t.Errorf("ExePath = %q, want %q — a block rule would have nothing to act on", got, want)
	}
}

// Homebrew keeps old versions beside the current one. A directory with three
// entries is one package, not three.
func TestHomebrewReportsOneRecordPerPackage(t *testing.T) {
	prefix := t.TempDir()
	old := writeCellar(t, prefix, "python", "3.11.0", true)
	writeCellar(t, prefix, "python", "3.12.0", true)

	// Make the older one genuinely older; the newest linked version is the
	// one that runs.
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	apps, err := (&HomebrewCollector{Prefixes: []string{prefix}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, a := range apps {
		if a.Name == "python" {
			found++
			if a.Version != "3.12.0" {
				t.Errorf("Version = %q, want the newest (3.12.0)", a.Version)
			}
		}
	}
	if found != 1 {
		t.Errorf("python appears %d times; old versions must not count as separate packages", found)
	}
}

// A cask whose payload is an application bundle is already in the catalogue
// under its real name — reporting it twice gives an operator a second row to
// write policy against that nothing can enforce.
func TestHomebrewSkipsCasksThatInstallAnApp(t *testing.T) {
	prefix := t.TempDir()
	appCask := filepath.Join(prefix, "Caskroom", "visual-studio-code", "1.95.0", "Visual Studio Code.app")
	if err := os.MkdirAll(appCask, 0o755); err != nil {
		t.Fatal(err)
	}
	pkgCask := filepath.Join(prefix, "Caskroom", "temurin", "21.0.1")
	if err := os.MkdirAll(pkgCask, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgCask, "jdk.pkg"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	apps := collect(t, &HomebrewCollector{Prefixes: []string{prefix}})

	if _, dup := apps["visual-studio-code"]; dup {
		t.Error("a cask that installs an .app was listed again; the bundle collector already has it")
	}
	if _, ok := apps["temurin"]; !ok {
		t.Error("a cask with no .app payload was dropped; nothing else would ever report it")
	}
}

func TestHomebrewOnAMachineWithoutItIsNotAnError(t *testing.T) {
	apps, err := (&HomebrewCollector{Prefixes: []string{t.TempDir()}}).Collect(context.Background())
	if err != nil {
		t.Errorf("a machine with no Homebrew reported an error: %v", err)
	}
	if len(apps) != 0 {
		t.Errorf("found %d packages where none exist", len(apps))
	}
}

// --- Chocolatey ------------------------------------------------------------

func writeChocoPackage(t *testing.T, root, dir, nuspec string) {
	t.Helper()
	pkg := filepath.Join(root, "lib", dir)
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, dir+".nuspec"), []byte(nuspec), 0o644); err != nil {
		t.Fatal(err)
	}
}

const chromeNuspec = `<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>googlechrome</id>
    <version>131.0.6778.86</version>
    <title>Google Chrome</title>
    <authors>Google Inc.</authors>
    <owners>chocolatey-community</owners>
  </metadata>
</package>`

// Portable Chocolatey packages register no uninstall entry at all, so to the
// registry collector they do not exist — and installing one needs no admin
// rights, which is exactly the case least-privilege work is about.
func TestChocolateyReadsThePackageLibrary(t *testing.T) {
	root := t.TempDir()
	writeChocoPackage(t, root, "googlechrome", chromeNuspec)

	apps := collect(t, &ChocolateyCollector{Root: root})

	app, ok := apps["Google Chrome"]
	if !ok {
		t.Fatalf("Google Chrome is missing; got %v", apps)
	}
	if app.Version != "131.0.6778.86" {
		t.Errorf("Version = %q", app.Version)
	}
	// Authors is the software's publisher; owners is whoever maintains the
	// Chocolatey package, which is usually a volunteer and not the vendor a
	// publisher rule means.
	if app.Publisher != "Google Inc." {
		t.Errorf("Publisher = %q, want the authors and not the package owner", app.Publisher)
	}
	if app.Source != SourceChocolatey {
		t.Errorf("Source = %q, want %q", app.Source, SourceChocolatey)
	}
}

// An operator searching the catalogue types "Google Chrome", not
// "googlechrome".
func TestChocolateyPrefersTheHumanName(t *testing.T) {
	root := t.TempDir()
	writeChocoPackage(t, root, "nodejs", `<?xml version="1.0"?><package><metadata>
		<id>nodejs</id><version>22.0.0</version><authors>Node.js Foundation</authors>
	</metadata></package>`)

	apps := collect(t, &ChocolateyCollector{Root: root})
	// With no title, the id is the only name there is.
	if _, ok := apps["nodejs"]; !ok {
		t.Errorf("a package with no title was dropped; got %v", apps)
	}
}

func TestChocolateyFindsTheShim(t *testing.T) {
	root := t.TempDir()
	writeChocoPackage(t, root, "googlechrome", chromeNuspec)

	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "googlechrome.exe"), []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}

	apps := collect(t, &ChocolateyCollector{Root: root})
	want := filepath.Join(bin, "googlechrome.exe")
	if got := apps["Google Chrome"].ExePath; got != want {
		t.Errorf("ExePath = %q, want the shim at %q", got, want)
	}
}

func TestChocolateyOnAMachineWithoutItIsNotAnError(t *testing.T) {
	apps, err := (&ChocolateyCollector{Root: t.TempDir()}).Collect(context.Background())
	if err != nil {
		t.Errorf("a machine with no Chocolatey reported an error: %v", err)
	}
	if len(apps) != 0 {
		t.Errorf("found %d packages where none exist", len(apps))
	}
}

// --- MultiCollector --------------------------------------------------------

type stubCollector struct {
	name string
	apps []Application
	err  error
}

func (s *stubCollector) Name() string { return s.name }
func (s *stubCollector) Collect(context.Context) ([]Application, error) {
	return s.apps, s.err
}

// One source failing must cost that source and not the scan. A machine with no
// Homebrew is the normal case, not an error, and an unreadable registry hive
// must not take the application bundles down with it.
func TestMultiCollectorKeepsGoingPastAFailure(t *testing.T) {
	m := &MultiCollector{Collectors: []Collector{
		&stubCollector{name: "bundles", apps: []Application{{ID: "a", Name: "Slack"}}},
		&stubCollector{name: "broken", err: context.DeadlineExceeded},
		&stubCollector{name: "brew", apps: []Application{{ID: "b", Name: "kubectl"}}},
	}}

	apps, err := m.Collect(context.Background())
	if err == nil {
		t.Error("the failure was swallowed; the backend would treat a partial scan as complete and sweep")
	}
	if len(apps) != 2 {
		t.Fatalf("got %d applications, want both working collectors' results", len(apps))
	}
}

func TestMultiCollectorDeduplicates(t *testing.T) {
	// The same product reported by two sources — a Chocolatey package that
	// also wrote an uninstall entry — must be one row, not two.
	m := &MultiCollector{Collectors: []Collector{
		&stubCollector{apps: []Application{{ID: "same", Name: "Chrome"}}},
		&stubCollector{apps: []Application{{ID: "same", Name: "Chrome", Publisher: "Google"}}},
	}}

	apps, err := m.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Fatalf("got %d rows for one application", len(apps))
	}
	if apps[0].Publisher != "Google" {
		t.Error("the sparser duplicate won; a record with more detail must not be blanked out")
	}
}

// The command is frequently not the package name: awscli provides aws,
// cocoapods provides pod. Recording the package name as the executable gives a
// block rule a path that does not exist.
func TestHomebrewFindsACommandNamedDifferentlyFromThePackage(t *testing.T) {
	prefix := t.TempDir()
	versionDir := writeCellar(t, prefix, "awscli", "2.35.15", true)

	pkgBin := filepath.Join(versionDir, "bin")
	linkBin := filepath.Join(prefix, "bin")
	for _, d := range []string{pkgBin, linkBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"aws", "aws_completer"} {
		if err := os.WriteFile(filepath.Join(pkgBin, command), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(pkgBin, command), filepath.Join(linkBin, command)); err != nil {
			t.Fatal(err)
		}
	}

	apps := collect(t, &HomebrewCollector{Prefixes: []string{prefix}})
	want := filepath.Join(linkBin, "aws")
	if got := apps["awscli"].ExePath; got != want {
		t.Errorf("ExePath = %q, want %q — aws_completer is a helper, not the product", got, want)
	}
}

// An unlinked binary is one nothing runs by name, so it must not be chosen
// over a linked one — and must not be chosen at all when nothing is linked.
func TestHomebrewIgnoresUnlinkedCommands(t *testing.T) {
	prefix := t.TempDir()
	versionDir := writeCellar(t, prefix, "somepkg", "1.0", true)

	pkgBin := filepath.Join(versionDir, "bin")
	if err := os.MkdirAll(pkgBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgBin, "internal-helper"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	apps := collect(t, &HomebrewCollector{Prefixes: []string{prefix}})
	if got := apps["somepkg"].ExePath; got != "" {
		t.Errorf("ExePath = %q, want empty — nothing was linked onto the PATH", got)
	}
}
