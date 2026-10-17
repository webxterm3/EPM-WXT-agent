//go:build darwin

package appinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Absolute paths, not PATH lookups: this runs as root, and resolving a helper
// through an inherited PATH is how a daemon ends up running someone else's
// binary.
const (
	plutilPath   = "/usr/bin/plutil"
	codesignPath = "/usr/bin/codesign"
)

// DefaultSearchRoots are the places macOS applications actually live.
//
// /System/Applications is included because an operator writing application
// control needs to see Terminal and friends — those are exactly the ones a
// least-privilege policy has an opinion about.
var DefaultSearchRoots = []string{
	"/Applications",
	"/System/Applications",
	"/Library/Application Support/JAMF/Applications",
}

// maxSearchDepth bounds the walk below each root.
//
// Vendors nest applications a level or two deep ("/Applications/Adobe/..."),
// but nothing legitimate is deeper, and an unbounded walk of /Applications on
// a machine with large app bundles is a lot of pointless I/O.
const maxSearchDepth = 3

// DarwinCollector reads installed applications from the filesystem.
type DarwinCollector struct {
	// Roots to search. Empty means DefaultSearchRoots.
	Roots []string

	// SkipSignatures turns off the codesign call.
	//
	// It exists for tests and for a deliberate operator choice, and it must
	// NOT be used to make a scan cheaper behind somebody's back.
	//
	// Enforcement once ran with this on, for speed. The publisher field came
	// back empty for roughly half the applications on a Mac, every rule that
	// named a publisher silently matched nothing, and the diagnostic — which
	// used the full collector — cheerfully reported that the same rule DID
	// match. Two collectors, two answers, and the one nobody could see was
	// the one that decided. Hence the cache below instead.
	SkipSignatures bool

	// sigCache remembers signatures between scans, keyed by bundle and
	// modification time.
	//
	// Reading a signature is one codesign process per application and is the
	// whole cost of a macOS scan. Enforcement re-scans every couple of
	// minutes, so without this the choice is a slow loop or a blind one. A
	// bundle that has not been modified cannot have been re-signed, so its
	// entry stays valid; one that has been modified misses the cache and is
	// read again, which is exactly when it must be.
	sigMu    sync.Mutex
	sigCache map[string]cachedSignature

	// SkipHomeDirectories turns off the per-user search.
	//
	// ~/Applications is where software installed without admin rights ends up,
	// which is exactly what least-privilege work cares about, so it is
	// searched by default. The agent runs as root and can read every profile.
	SkipHomeDirectories bool
}

// PlatformCollector returns the collector for this platform.
//
// Two sources, because macOS has two. Application bundles are what a user
// points at; Homebrew is how a developer's machine actually acquires most of
// the software it runs, and a formula leaves no bundle anywhere for the first
// collector to find.
func PlatformCollector() Collector {
	return &MultiCollector{
		Label:      "macos",
		Collectors: []Collector{&DarwinCollector{}, &HomebrewCollector{}},
	}
}

// FastPlatformCollector is the SAME collector as PlatformCollector.
//
// It used to be a cheaper variant with signature reading turned off, and that
// is how enforcement came to see an empty publisher for half the applications
// on a Mac: every rule naming a publisher matched nothing, while the
// diagnostic — which used the full collector — reported that it matched. Two
// collectors cannot be allowed to answer the same question differently, so
// there is now one, and the cost is handled by caching signatures rather than
// by not reading them.
//
// The name is kept because callers that run often should keep saying which
// they are; if a genuinely cheaper scan is ever needed it must drop something
// no policy can match on.
func FastPlatformCollector() Collector { return PlatformCollector() }

func (c *DarwinCollector) Name() string { return "macos-bundles" }

func (c *DarwinCollector) roots() []string {
	if len(c.Roots) > 0 {
		return c.Roots
	}
	roots := append([]string{}, DefaultSearchRoots...)
	if !c.SkipHomeDirectories {
		roots = append(roots, homeApplicationDirs()...)
	}
	return roots
}

// UserApplicationDirs is each user profile's own Applications folder.
//
// Exported because application control watches the same places the inventory
// reads: software installed without admin rights lands here, which is exactly
// what a least-privilege policy is written about.
func UserApplicationDirs() []string { return homeApplicationDirs() }

// homeApplicationDirs returns each user profile's own Applications folder.
//
// These are listed explicitly rather than by walking /Users, so the scan never
// descends into somebody's Documents or Downloads — this is an inventory of
// installed software, not a search of people's files.
func homeApplicationDirs() []string {
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return nil
	}

	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "Shared" || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		dir := filepath.Join("/Users", entry.Name(), "Applications")
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// Collect walks the search roots for application bundles.
//
// A root that does not exist, or that cannot be read, is skipped rather than
// failing the scan: a missing /Library/Application Support path is the normal
// case on most machines, not an error.
func (c *DarwinCollector) Collect(ctx context.Context) ([]Application, error) {
	var apps []Application

	for _, root := range c.roots() {
		if ctx.Err() != nil {
			return finalise(apps), ctx.Err()
		}
		for _, bundle := range findBundles(root, maxSearchDepth) {
			if ctx.Err() != nil {
				return finalise(apps), ctx.Err()
			}
			if app, ok := c.readBundle(ctx, bundle); ok {
				apps = append(apps, app)
			}
		}
	}
	return finalise(apps), nil
}

// findBundles returns the .app directories under root.
//
// It does not descend into a bundle once found: an application contains its
// own helper apps and XPC services, none of which are separately installed
// software, and walking into them multiplies the result by ten for no gain.
func findBundles(root string, depth int) []string {
	if depth <= 0 {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if strings.HasSuffix(entry.Name(), ".app") {
			out = append(out, path)
			continue
		}
		out = append(out, findBundles(path, depth-1)...)
	}
	return out
}

// readBundle reads one application's metadata.
func (c *DarwinCollector) readBundle(ctx context.Context, path string) (Application, bool) {
	info, ok := readInfoPlist(ctx, filepath.Join(path, "Contents", "Info.plist"))
	if !ok {
		// No readable Info.plist means this is not an application bundle, or
		// it is damaged. Either way there is nothing to report about it.
		return Application{}, false
	}

	authority := ""
	if !c.SkipSignatures {
		authority = c.signatureFor(ctx, path)
	}

	app, ok := applicationFromBundle(path, info, authority)
	if !ok {
		return Application{}, false
	}
	if t, err := bundleModTime(path); err == nil {
		// macOS records no install date, so the bundle's own modification time
		// is the closest available signal. It is approximate — a self-updating
		// application resets it — and is labelled as a date, not a guarantee.
		app.InstalledAt = t
	}
	return app, true
}

// readInfoPlist decodes an Info.plist via plutil.
//
// plutil is used rather than a plist library because Info.plist is usually in
// Apple's binary format, which the standard library cannot read, and shelling
// out to the system tool keeps this free of a third-party dependency — the
// same choice the agent already makes for `log show`, `ioreg` and `dscl`.
func readInfoPlist(ctx context.Context, path string) (bundleInfo, bool) {
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, plutilPath, "-convert", "json", "-o", "-", path)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return bundleInfo{}, false
	}

	var info bundleInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		return bundleInfo{}, false
	}
	return info, true
}

// readCodesignAuthority returns the bundle's signing identity, or "" when it
// is unsigned or cannot be read. Failure is not an error: an unsigned
// application is a perfectly ordinary thing to find, and is itself worth
// knowing about.
// cachedSignature is one bundle's signing authority, and the modification
// time it was read at.
type cachedSignature struct {
	modTime   time.Time
	authority string
}

// signatureFor returns a bundle's signing authority, reading it at most once
// per modification.
func (c *DarwinCollector) signatureFor(ctx context.Context, path string) string {
	mod, err := bundleModTime(path)
	if err != nil {
		// No modification time to key on, so nothing can be cached safely.
		return readCodesignAuthority(ctx, path)
	}

	c.sigMu.Lock()
	hit, ok := c.sigCache[path]
	c.sigMu.Unlock()
	if ok && hit.modTime.Equal(mod) {
		return hit.authority
	}

	authority := readCodesignAuthority(ctx, path)
	if authority == "" {
		// A failure is NOT cached.
		//
		// An empty answer means codesign could not be run, was cut short by
		// the enclosing timeout, or the bundle genuinely is unsigned — and
		// nothing here can tell those apart. Remembering it would turn one
		// slow scan into a permanently blind one for that application, which
		// is precisely the failure this cache exists alongside: a publisher
		// that is empty on the endpoint and populated in the portal, so every
		// rule naming it silently matches nothing.
		//
		// An unsigned bundle therefore pays for a codesign call every scan.
		// That is the right way round: the cost is bounded and visible, and
		// the alternative is wrong answers that are neither.
		return ""
	}

	c.sigMu.Lock()
	if c.sigCache == nil {
		c.sigCache = make(map[string]cachedSignature)
	}
	c.sigCache[path] = cachedSignature{modTime: mod, authority: authority}
	c.sigMu.Unlock()
	return authority
}

func readCodesignAuthority(ctx context.Context, path string) string {
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// codesign writes its report to stderr, not stdout.
	cmd := exec.CommandContext(runCtx, codesignPath, "-dv", "--verbose=4", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()

	return parseCodesignAuthority(stderr.String())
}

func bundleModTime(path string) (time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("stat bundle: %w", err)
	}
	return fi.ModTime().UTC(), nil
}
