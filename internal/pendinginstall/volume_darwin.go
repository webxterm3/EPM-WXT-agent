//go:build darwin

package pendinginstall

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Noticing that somebody opened a disk image, rather than that one exists.
//
// The first version of this read everybody's Downloads folder. It was wrong
// for two reasons: a long-lived download folder is full of images somebody
// downloaded months ago and does not care about, so the list was noise; and
// the file sitting there is not a decision anybody made.
//
// Double-clicking IS the decision. It mounts the image under /Volumes, which
// is a cheap thing to watch, happens exactly when somebody is about to
// install, and hands over the real application bundle — so the name,
// publisher and bundle id come from the thing being installed rather than
// from a filename anybody can type.
//
// That last part matters more than it looks. `codesign` on the bundle inside
// the image returns the SAME authority string the inventory records for an
// installed application — "Developer ID Application: Microsoft Corporation
// (UBF8T346G9)". A rule written from the Applications tab therefore matches
// its own installer exactly, with no reformatting and no second way to say
// the same thing.

// volumesDir is where macOS mounts removable and disk-image volumes. A var
// so a test can point the scan at a directory it controls; nothing changes it
// at runtime.
var volumesDir = "/Volumes"

// MountedApp is an application bundle sitting in a mounted disk image.
type MountedApp struct {
	// Volume is the mount point, used to tell one mount from another and to
	// notice when it goes away.
	Volume string
	// BundlePath is the .app inside it.
	BundlePath string

	Name      string
	BundleID  string
	Version   string
	Publisher string

	MountedAt time.Time
}

// authorityLine is codesign's first authority, which names the signer.
var authorityLine = regexp.MustCompile(`(?m)^Authority=(.+)$`)

// MountedApps returns the application bundles in currently mounted images.
//
// The boot volume is skipped: /Volumes holds a link to it, and treating the
// running system as a disk image somebody just opened would offer to install
// everything on the machine.
func MountedApps() []MountedApp {
	entries, err := os.ReadDir(volumesDir)
	if err != nil {
		return nil
	}

	var out []MountedApp
	for _, e := range entries {
		vol := filepath.Join(volumesDir, e.Name())
		if isBootVolume(vol) {
			continue
		}
		app, ok := appInVolume(vol)
		if !ok {
			continue
		}
		out = append(out, app)
	}

	forgetUnmountedSigners(out)
	return out
}

// VolumeNames lists what is mounted, and nothing else.
//
// One directory listing, no bundle inspection, no codesign, no plist. It
// exists so the agent can notice a disk image appearing within a fraction of
// a second without paying for a decision several times a second: somebody
// double-clicks an image and drags almost immediately, and anything the
// agent has not decided by then meets the administrator password sheet
// instead.
func VolumeNames() []string {
	entries, err := os.ReadDir(volumesDir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// isBootVolume reports whether this mount point is the running system.
func isBootVolume(vol string) bool {
	// /Volumes/Macintosh HD is a firmlink to /, so the two resolve to the
	// same place. Compared by identity rather than by name, because the boot
	// volume can be called anything.
	a, errA := os.Stat(vol)
	b, errB := os.Stat("/")
	return errA == nil && errB == nil && os.SameFile(a, b)
}

// appInVolume finds the one application bundle in a mounted image.
//
// Exactly one, and only at the top level. An image with two is ambiguous, and
// descending into it would find the bundles vendors ship inside their own
// apps — a helper buried three levels down is not what somebody double-clicked
// to install.
func appInVolume(vol string) (MountedApp, bool) {
	entries, err := os.ReadDir(vol)
	if err != nil {
		return MountedApp{}, false
	}

	var found string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".app") {
			continue
		}
		if found != "" {
			// More than one: there is no single thing being installed.
			return MountedApp{}, false
		}
		found = filepath.Join(vol, e.Name())
	}
	if found == "" {
		return MountedApp{}, false
	}

	app := MountedApp{
		Volume:     vol,
		BundlePath: found,
		Name:       strings.TrimSuffix(filepath.Base(found), ".app"),
		MountedAt:  time.Now(),
	}
	app.BundleID, app.Version, app.Name = bundleIdentity(found, app.Name)
	app.Publisher = verifiedBundleSigner(found)
	return app, true
}

// bundleIdentity reads what the application calls itself.
func bundleIdentity(bundle, fallbackName string) (bundleID, version, name string) {
	plist := filepath.Join(bundle, "Contents", "Info.plist")
	read := func(key string) string {
		out, err := exec.Command("/usr/libexec/PlistBuddy",
			"-c", "Print :"+key, plist).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}

	bundleID = read("CFBundleIdentifier")
	version = read("CFBundleShortVersionString")

	// The FOLDER name wins over the plist's own, for the same reason the
	// inventory prefers it: Visual Studio Code calls itself "Code" in
	// CFBundleName, and nobody looking at their Applications folder would
	// recognise that.
	name = fallbackName
	return bundleID, version, name
}

// verifiedBundleSigner returns who signed an application, or empty when
// nothing vouches for it.
//
// --verify FIRST, and its exit code is the answer. The inventory's own
// signature reader runs `codesign -dv` and parses the display output without
// checking whether the verification passed — fine for a label in a list, and
// a fake check here, where the answer decides whether something is installed
// with full privilege.
func verifiedBundleSigner(bundle string) string {
	key, ok := bundleFingerprint(bundle)
	if ok {
		signerMu.Lock()
		cached, hit := signerCache[key]
		signerMu.Unlock()
		if hit {
			return cached
		}
	}

	signer := runCodesign(bundle)

	// Only a SUCCESSFUL answer is remembered.
	//
	// An empty result means one of two things that cannot be told apart
	// here: the bundle genuinely carries no usable signature, or the check
	// did not get a straight answer this time. Mounting a disk image is not
	// atomic, and the scan runs every three seconds, so the very first look
	// at a volume can land while it is still appearing.
	//
	// Caching the empty answer made that race permanent. The key is the
	// device and inode, which do not change while the image stays mounted,
	// so one unlucky first scan left the application unverified for as long
	// as it was open — no drag window, and Finder asking for an
	// administrator password, on software that is in fact properly signed.
	// Re-opening the image did not help, because it was the same volume.
	//
	// Not caching it costs almost nothing: codesign --verify on a bundle
	// with no signature returns in about ten milliseconds, because there is
	// no signature to walk. The expensive case is the signed one, and that
	// is the case that gets cached.
	if ok && signer != "" {
		signerMu.Lock()
		signerCache[key] = signer
		signerMu.Unlock()
	}
	return signer
}

// Verifying a mounted image once, not every few seconds.
//
// codesign --deep --strict walks every file in the bundle. On something the
// size of Xcode that is seconds of CPU, and the volume scan would otherwise
// repeat it for as long as the image stays mounted — which is exactly while
// somebody is sitting there waiting to install it.
//
// The entry is keyed on the mounted device and inode as well as the path,
// because /Volumes/Installer is a name macOS reuses: eject one image, open
// another that calls its volume the same thing, and the path alone would
// hand back the first image's signer for the second image's contents.
var (
	signerMu    sync.Mutex
	signerCache = map[signerKey]string{}
)

type signerKey struct {
	bundle string
	dev    uint64
	ino    uint64
}

// bundleFingerprint identifies which bundle this actually is. It reports
// false when the bundle cannot be stat'd, and then nothing is cached —
// guessing an identity is how the wrong signer gets reused.
func bundleFingerprint(bundle string) (signerKey, bool) {
	fi, err := os.Stat(bundle)
	if err != nil {
		return signerKey{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return signerKey{}, false
	}
	return signerKey{bundle: bundle, dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

// forgetUnmountedSigners drops entries for bundles that are no longer there,
// so the cache does not grow for the life of the agent.
func forgetUnmountedSigners(live []MountedApp) {
	keep := make(map[signerKey]bool, len(live))
	for _, app := range live {
		if key, ok := bundleFingerprint(app.BundlePath); ok {
			keep[key] = true
		}
	}

	signerMu.Lock()
	defer signerMu.Unlock()
	for key := range signerCache {
		if !keep[key] {
			delete(signerCache, key)
		}
	}
}

// runCodesign is the real verification, split out so the cache can be tested
// without a signed bundle to point it at.
var runCodesign = func(bundle string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "/usr/bin/codesign",
		"--verify", "--deep", "--strict", bundle).Run(); err != nil {
		return ""
	}

	out, err := exec.CommandContext(ctx, "/usr/bin/codesign",
		"-dv", "--verbose=4", bundle).CombinedOutput()
	if err != nil {
		return ""
	}

	// The FIRST authority is the signer; the ones after it are the chain up
	// to Apple's root, and reporting one of those would name a certificate
	// authority as the publisher of everything.
	m := authorityLine.FindSubmatch(out)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// ConsoleUser is whoever is logged in at the screen.
//
// The owner of /dev/console, which is how macOS itself answers the question.
// It matters here because a disk image is mounted system-wide while the
// person dragging out of it is the one sitting in front of the machine —
// granting the window to anybody else would grant it to somebody who is not
// there.
//
// Empty at the login window, or when nobody is logged in. Callers must treat
// that as "no window", never as "everybody".
func ConsoleUser() string {
	out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return ""
	}
	user := strings.TrimSpace(string(out))
	// Nobody is at the screen: macOS parks the console on root at the login
	// window and on _mbsetupuser during setup.
	if user == "root" || user == "_mbsetupuser" || user == "" {
		return ""
	}
	return user
}
