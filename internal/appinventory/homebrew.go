package appinventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Homebrew sources. The distinction is not cosmetic: a machine with twenty
// packages somebody asked for typically has eighty more pulled in behind them,
// and a catalogue that lists all hundred the same way buries the twenty that
// anybody made a decision about.
const (
	SourceHomebrew     = "homebrew"
	SourceHomebrewDep  = "homebrew-dependency"
	SourceHomebrewCask = "homebrew-cask"
)

// HomebrewPublisher is recorded as the publisher so that "block everything
// installed by Homebrew" is one publisher rule rather than a list of names.
const HomebrewPublisher = "Homebrew"

// DefaultHomebrewPrefixes are where Homebrew installs.
//
// Both are listed because the prefix differs by architecture — /opt/homebrew
// on Apple silicon, /usr/local on Intel — and a machine that has been migrated
// between them legitimately has both.
var DefaultHomebrewPrefixes = []string{"/opt/homebrew", "/usr/local"}

// HomebrewCollector reads Homebrew's own directories.
//
// It reads the filesystem rather than running `brew`. The agent runs as root,
// Homebrew refuses to run as root, and dropping privileges to each user who
// might own a prefix in order to ask a Ruby program what it installed is a
// great deal of machinery for information that is sitting in a directory
// listing. Reading Cellar and Caskroom also works when Homebrew is broken,
// half-upgraded, or mid-install — states a managed fleet is full of.
type HomebrewCollector struct {
	// Prefixes to search. Empty means DefaultHomebrewPrefixes.
	Prefixes []string

	// IncludeDependencies reports packages that were pulled in by other
	// packages rather than asked for. On by default — an inventory that hides
	// software because of how it got there is an inventory with holes — but
	// they are labelled, so the portal can fold them away.
	ExcludeDependencies bool
}

func (c *HomebrewCollector) Name() string { return "homebrew" }

func (c *HomebrewCollector) prefixes() []string {
	if len(c.Prefixes) > 0 {
		return c.Prefixes
	}
	return DefaultHomebrewPrefixes
}

// Collect reads every Homebrew prefix on the machine.
func (c *HomebrewCollector) Collect(ctx context.Context) ([]Application, error) {
	var apps []Application
	for _, prefix := range c.prefixes() {
		if ctx.Err() != nil {
			return apps, ctx.Err()
		}
		apps = append(apps, c.collectFormulae(ctx, prefix)...)
		apps = append(apps, c.collectCasks(ctx, prefix)...)
	}
	return apps, nil
}

// collectFormulae reads <prefix>/Cellar, which holds command-line packages.
//
// These are invisible to every other collector: a formula installs no bundle,
// writes no registry key and appears in no Applications folder. Software a
// developer actually runs all day — node, python, kubectl — is here and
// nowhere else.
func (c *HomebrewCollector) collectFormulae(ctx context.Context, prefix string) []Application {
	cellar := filepath.Join(prefix, "Cellar")
	entries, err := os.ReadDir(cellar)
	if err != nil {
		return nil
	}

	var apps []Application
	for _, entry := range entries {
		if ctx.Err() != nil {
			return apps
		}
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		name := entry.Name()
		version, versionDir := newestVersionDir(filepath.Join(cellar, name))
		if version == "" {
			continue
		}

		receipt := readInstallReceipt(filepath.Join(versionDir, "INSTALL_RECEIPT.json"))
		source := SourceHomebrew
		if !receipt.InstalledOnRequest {
			if c.ExcludeDependencies {
				continue
			}
			source = SourceHomebrewDep
		}

		apps = append(apps, Application{
			ID:          "homebrew:" + name,
			Name:        name,
			Version:     version,
			Publisher:   HomebrewPublisher,
			InstallPath: versionDir,
			ExePath:     formulaExecutable(prefix, name, versionDir),
			Scope:       ScopeMachine,
			Source:      source,
			InstalledAt: receipt.installedAt(),
			Arch:        receipt.Arch,
		})
	}
	return apps
}

// collectCasks reads <prefix>/Caskroom, which holds packaged applications.
//
// A cask whose payload is an application bundle is deliberately skipped: brew
// puts that bundle in /Applications, where the bundle collector already finds
// it with its real name, identifier and signature. Reporting it here as well
// would show the same application twice in the catalogue and, worse, give an
// operator a second row to write policy against that nothing can enforce —
// locking a Caskroom directory does not stop anything launching.
func (c *HomebrewCollector) collectCasks(ctx context.Context, prefix string) []Application {
	caskroom := filepath.Join(prefix, "Caskroom")
	entries, err := os.ReadDir(caskroom)
	if err != nil {
		return nil
	}

	var apps []Application
	for _, entry := range entries {
		if ctx.Err() != nil {
			return apps
		}
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		name := entry.Name()
		caskDir := filepath.Join(caskroom, name)
		version, versionDir := newestVersionDir(caskDir)
		if version == "" {
			continue
		}
		if containsAppBundle(versionDir) {
			continue
		}

		receipt := readInstallReceipt(filepath.Join(caskDir, ".metadata", "INSTALL_RECEIPT.json"))

		apps = append(apps, Application{
			ID:          "homebrew-cask:" + name,
			Name:        name,
			Version:     version,
			Publisher:   HomebrewPublisher,
			InstallPath: versionDir,
			Scope:       ScopeMachine,
			Source:      SourceHomebrewCask,
			InstalledAt: receipt.installedAt(),
		})
	}
	return apps
}

// newestVersionDir picks the version to report for a package.
//
// Homebrew keeps old versions alongside the current one, so a directory with
// three entries is one package, not three. The most recently modified wins
// rather than the highest-sorting name: version strings are not comparable as
// text ("1.10" sorts below "1.9"), and the one brew last linked is the one
// that runs.
func newestVersionDir(dir string) (version, path string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}
	var newest time.Time
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if path == "" || info.ModTime().After(newest) {
			newest = info.ModTime()
			version = e.Name()
			path = filepath.Join(dir, e.Name())
		}
	}
	return version, path
}

// containsAppBundle reports whether a cask's payload is a macOS application.
func containsAppBundle(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".app") {
			return true
		}
	}
	return false
}

// formulaExecutable is the command a formula actually puts on the PATH.
//
// It matters for enforcement rather than for display: blocking a formula means
// acting on the binary that gets run, and <prefix>/bin/<command> is the
// symlink everything resolves through.
//
// The command is frequently NOT the package name — awscli provides aws,
// cocoapods provides pod — so when the obvious name is absent the package's
// own bin and sbin directories are read and the linked commands matched
// against it.
//
// One honest limitation: a formula can provide several commands (awscli
// provides aws and aws_completer), and only the primary one is recorded here,
// so a block rule acts on that one. Reporting each command as its own
// application would be more thorough and would turn a catalogue of a hundred
// packages into one of several hundred entries nobody can read.
func formulaExecutable(prefix, name, versionDir string) string {
	// The package name as the command: right most of the time, and cheap.
	for _, c := range []string{
		filepath.Join(prefix, "bin", name),
		filepath.Join(versionDir, "bin", name),
		filepath.Join(versionDir, "sbin", name),
	} {
		if _, err := os.Lstat(c); err == nil {
			return c
		}
	}

	// Otherwise take what the package actually installed, preferring a command
	// that Homebrew linked onto the PATH — an unlinked binary is one nothing
	// runs by name.
	var best string
	for _, dir := range []string{"bin", "sbin"} {
		entries, err := os.ReadDir(filepath.Join(versionDir, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			command := e.Name()
			linked := filepath.Join(prefix, "bin", command)
			if _, err := os.Lstat(linked); err != nil {
				continue
			}
			if betterCommandFor(name, command, filepath.Base(best)) {
				best = linked
			}
		}
	}
	return best
}

// betterCommandFor picks between two commands a package provides.
//
// A command whose name is contained in the package name wins — "aws" for
// awscli — because that is the product's own name rather than a helper built
// from it. Failing that the shortest wins, which picks "pod" over "xcodeproj"
// and is right far more often than it is wrong.
func betterCommandFor(pkg, candidate, current string) bool {
	if current == "" {
		return true
	}
	cHit := strings.Contains(pkg, candidate)
	curHit := strings.Contains(pkg, current)
	if cHit != curHit {
		return cHit
	}
	return len(candidate) < len(current)
}

// installReceipt is the part of Homebrew's INSTALL_RECEIPT.json worth reading.
type installReceipt struct {
	InstalledOnRequest bool   `json:"installed_on_request"`
	Time               int64  `json:"time"`
	Arch               string `json:"arch"`
}

func (r installReceipt) installedAt() time.Time {
	if r.Time <= 0 {
		return time.Time{}
	}
	return time.Unix(r.Time, 0).UTC()
}

// readInstallReceipt reads a receipt, treating an unreadable one as a package
// that was asked for.
//
// The default matters: a missing receipt means an older Homebrew or a manual
// installation, and reporting those as dependencies would file real software
// under "pulled in by something else" where nobody looks for it.
func readInstallReceipt(path string) installReceipt {
	r := installReceipt{InstalledOnRequest: true}
	data, err := os.ReadFile(path) // #nosec G304 -- a path derived from a directory listing the agent walked
	if err != nil {
		return r
	}
	var parsed installReceipt
	if err := json.Unmarshal(data, &parsed); err != nil {
		return r
	}
	return parsed
}
