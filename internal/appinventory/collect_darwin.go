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
	// Signature reading is one process per application, which is the slow part
	// of a scan. It is on by default because publisher is the single most
	// useful field for writing policy — "allow anything signed by us" is the
	// rule most organisations actually want — but it can be turned off on a
	// machine where the scan cost matters more.
	SkipSignatures bool

	// SkipHomeDirectories turns off the per-user search.
	//
	// ~/Applications is where software installed without admin rights ends up,
	// which is exactly what least-privilege work cares about, so it is
	// searched by default. The agent runs as root and can read every profile.
	SkipHomeDirectories bool
}

// PlatformCollector returns the collector for this platform.
func PlatformCollector() Collector { return &DarwinCollector{} }

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
		authority = readCodesignAuthority(ctx, path)
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
