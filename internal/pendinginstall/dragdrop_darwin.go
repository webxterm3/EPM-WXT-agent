//go:build darwin

package pendinginstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Letting somebody drag an approved application into /Applications.
//
// Dragging an app onto the Applications folder IS how software is installed
// on a Mac. A standard user cannot: /Applications is root:admin, so Finder
// asks for an administrator's password and the person is stopped by a dialog
// that explains nothing about policy.
//
// The agent cannot intercept that drag — Finder is Apple's and hooking it
// needs an Endpoint Security entitlement this product does not hold. What it
// CAN do is make the drag succeed, for that person, for a few minutes,
// because an installer they are allowed to install is sitting in their
// downloads.
//
// # Why an ACL and not the admin group
//
// Adding somebody to `admin` would also work, and it is what the first
// sketch of this did. It gives far too much: the admin group is in sudoers,
// so for the length of the window that person can run anything as root —
// including stopping this agent. A management product that hands out the
// ability to switch itself off has given away more than the problem was
// worth.
//
// A POSIX ACL grants write on ONE DIRECTORY to ONE USER. They can put an
// application into /Applications and nothing else: no sudo, no System
// Settings, no touching the agent.
//
// # What the window still allows
//
// During it they can drag in some OTHER application, not only the approved
// one. That is the honest cost, and it is bounded: the grant only opens
// because an approved installer is present, it is add-only so nothing
// already installed can be removed, it closes as soon as something lands,
// and application control sweeps what policy forbids within a couple of
// minutes of it arriving.

// applicationsDir is the only directory ever granted.
var applicationsDir = "/Applications"

// dragWindow is how long a grant lasts if nothing is installed.
//
// Long enough to mount an image, read the vendor's "drag me here" picture and
// drag; short enough that a forgotten grant is not a standing permission.
const dragWindow = 10 * time.Minute

// aclRights is add-only, deliberately.
//
// delete_child is NOT granted: with it, the window would also let somebody
// remove applications that are already installed, which is a different and
// much larger thing than putting a new one in.
//
// Replacing or removing an application is handled separately, by granting
// `delete` on THAT ONE BUNDLE — see GrantBundleRemoval. Measured: on macOS
// that is sufficient to remove it even when the parent directory denies
// delete_child, so upgrading and uninstalling work without ever opening
// /Applications as a whole to deletion.
const aclRights = "add_file,add_subdirectory"

// removeRights is granted on one application bundle, never on a directory.
//
// `delete` on the bundle is what lets Finder replace it during an upgrade
// and what lets somebody drag it to the Trash. Scoped per application
// because the question policy answers is per application: being allowed to
// remove Slack is not being allowed to remove the security tooling next to
// it.
const removeRights = "delete"

// dragGrants tracks what is open, so each can be closed exactly once.
// bundleGrants does the same for per-application removal, keyed by user and
// bundle path together.
var (
	dragMu       sync.Mutex
	dragGrants   = map[string]time.Time{}
	bundleGrants = map[string]time.Time{}
)

func bundleKey(user, bundle string) string { return user + "\x00" + bundle }

// GrantBundleRemoval lets one user replace or remove ONE application.
//
// Idempotent, like the install window, because it is re-asserted on every
// scan for as long as policy allows that application.
func GrantBundleRemoval(user, bundle string) error {
	if user == "" || bundle == "" {
		return fmt.Errorf("no user or bundle to grant on")
	}
	// Never this product's own installation.
	//
	// A removal grant is handed to a standard user, and the agent is the
	// thing enforcing policy on the machine: letting it be dragged to the
	// Trash would make every other rule optional. A policy rule allowing
	// "wxt-agent" must not reach this, however it was written.
	if isOwnInstallPath(bundle) {
		return fmt.Errorf("refusing to grant removal of the agent's own files: %s", bundle)
	}

	dragMu.Lock()
	defer dragMu.Unlock()

	key := bundleKey(user, bundle)
	if until, open := bundleGrants[key]; open && time.Now().Before(until) {
		return nil
	}
	if err := applyBundleACL(bundle, user, true); err != nil {
		return err
	}
	bundleGrants[key] = time.Now().Add(dragWindow)
	return nil
}

// ownInstallPaths are this product's own files, which no grant ever covers.
// Mirrors the protected list in internal/appcontrol; both exist because the
// agent must not be removable by the people it manages.
var ownInstallPaths = []string{
	"/usr/local/bin/wxt-agent",
	"/opt/vsay",
	"/library/application support/vsay",
}

// ownBundleName is this product's own bundle inside the applications folder.
// Derived from applicationsDir rather than written out, so the check means
// the same thing wherever that points — a hardcoded "/applications/..."
// silently stopped matching the moment anything else moved.
func ownBundleName() string {
	return strings.ToLower(filepath.Join(applicationsDir, "wxt-agent.app"))
}

// IsOwnInstallPath reports whether a path belongs to this product.
func IsOwnInstallPath(path string) bool { return isOwnInstallPath(path) }

func isOwnInstallPath(path string) bool {
	clean := strings.ToLower(filepath.Clean(path))
	for _, own := range append(ownInstallPaths, ownBundleName()) {
		if clean == own || strings.HasPrefix(clean, own+"/") {
			return true
		}
	}
	return false
}

// RevokeBundleRemoval closes one application's removal grant.
func RevokeBundleRemoval(user, bundle string) {
	dragMu.Lock()
	defer dragMu.Unlock()
	key := bundleKey(user, bundle)
	if _, open := bundleGrants[key]; !open {
		return
	}
	_ = applyBundleACL(bundle, user, false)
	delete(bundleGrants, key)
}

// ExpireBundleGrants closes removal grants nothing has re-asserted.
//
// An application that stops being allowed — the rule changed, or the
// approval ran out — stops being removable at the next scan, because the
// grant is only renewed while policy still says yes.
func ExpireBundleGrants() {
	dragMu.Lock()
	stale := make([]string, 0)
	now := time.Now()
	for key, until := range bundleGrants {
		if now.After(until) {
			stale = append(stale, key)
		}
	}
	dragMu.Unlock()

	for _, key := range stale {
		user, bundle, _ := strings.Cut(key, "\x00")
		RevokeBundleRemoval(user, bundle)
	}
}

// RevokeBundleGrantsExcept closes every removal grant for this user except
// the ones named.
//
// How an application stops being removable the moment policy stops allowing
// it. Letting the ten-minute window run out instead would leave a rule
// change unapplied for ten minutes on every machine, which is long enough
// for somebody to act on the permission the rule just took away.
func RevokeBundleGrantsExcept(user string, keep map[string]bool) {
	dragMu.Lock()
	var drop []string
	for key := range bundleGrants {
		owner, bundle, _ := strings.Cut(key, "\x00")
		if owner == user && !keep[bundle] {
			drop = append(drop, bundle)
		}
	}
	dragMu.Unlock()

	for _, bundle := range drop {
		RevokeBundleRemoval(user, bundle)
	}
}

// RevokeAllBundleGrants closes every removal grant this process opened.
func RevokeAllBundleGrants() {
	dragMu.Lock()
	keys := make([]string, 0, len(bundleGrants))
	for key := range bundleGrants {
		keys = append(keys, key)
	}
	dragMu.Unlock()

	for _, key := range keys {
		user, bundle, _ := strings.Cut(key, "\x00")
		RevokeBundleRemoval(user, bundle)
	}
}

// InstalledApps names the application bundles in /Applications.
//
// Names only, read with one directory listing. Deliberately NOT reading each
// bundle's Info.plist: this runs on the scan loop, and a hundred PlistBuddy
// invocations every few seconds to answer a question the folder name already
// answers would be the agent making the machine slower.
func InstalledApps() []string {
	entries, err := os.ReadDir(applicationsDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".app") {
			out = append(out, filepath.Join(applicationsDir, e.Name()))
		}
	}
	return out
}

// RevokeStaleBundleGrants strips removal grants left by an earlier run.
//
// Same reasoning as RevokeStaleDragGrants: the entry is on the bundle and
// survives a crash and a reboot, and in-memory state is exactly what a
// killed process does not have.
func RevokeStaleBundleGrants() []string {
	var cleared []string
	for _, bundle := range InstalledApps() {
		for _, user := range usersWithRights(aclListing(bundle), removeRights) {
			if err := applyBundleACL(bundle, user, false); err == nil {
				cleared = append(cleared, user+" on "+filepath.Base(bundle))
			}
		}
	}
	return cleared
}

// applyBundleACL is the seam for the per-application grant.
var applyBundleACL = func(bundle, user string, add bool) error {
	return setRights(bundle, user, removeRights, add)
}

// GrantDragInstall lets one user put an application into /Applications.
//
// Idempotent: called on every scan for as long as an approved installer sits
// in that person's downloads, and only the first call changes anything.
func GrantDragInstall(user string) error {
	if user == "" {
		return fmt.Errorf("no user to grant to")
	}

	dragMu.Lock()
	defer dragMu.Unlock()

	if until, open := dragGrants[user]; open && time.Now().Before(until) {
		return nil
	}

	if err := applyACL(applicationsDir, user, true); err != nil {
		return err
	}
	dragGrants[user] = time.Now().Add(dragWindow)
	return nil
}

// RevokeDragInstall closes a user's window.
func RevokeDragInstall(user string) {
	if user == "" {
		return
	}
	dragMu.Lock()
	defer dragMu.Unlock()
	if _, open := dragGrants[user]; !open {
		return
	}
	_ = applyACL(applicationsDir, user, false)
	delete(dragGrants, user)
}

// ExpireDragGrants closes every window whose time is up.
//
// Called on a timer rather than relying on something noticing an install:
// a person who downloads an installer and never uses it would otherwise keep
// write access to /Applications until the agent restarted.
func ExpireDragGrants() {
	now := time.Now()

	dragMu.Lock()
	var expired []string
	for user, until := range dragGrants {
		if now.After(until) {
			expired = append(expired, user)
		}
	}
	dragMu.Unlock()

	for _, user := range expired {
		RevokeDragInstall(user)
	}
}

// RevokeAllDragGrants closes everything, for shutdown and uninstall.
//
// A grant left behind is a standing permission that nothing is watching, and
// an agent that stopped is exactly when nothing is watching.
func RevokeAllDragGrants() {
	dragMu.Lock()
	users := make([]string, 0, len(dragGrants))
	for u := range dragGrants {
		users = append(users, u)
	}
	dragMu.Unlock()

	for _, u := range users {
		RevokeDragInstall(u)
	}
}

// RevokeStaleDragGrants removes windows left open by an agent that stopped
// without closing them.
//
// Every other revocation works from what THIS process granted, which is the
// one thing a process that was killed, panicked or powered off does not
// have. The entry survives a reboot — it is on the directory, not in memory
// — so without this a single crash leaves a standing, unwatched write
// permission on /Applications for as long as the Mac exists. An uninstall
// left one behind too.
//
// Read from the directory itself and matched on the exact rights this
// package writes. An entry carrying any OTHER right is left alone: rights
// coalesce into one entry per user, so a wider one is not something this
// package can claim to have made, and removing somebody else's deliberate
// grant would be worse than leaving ours.
func RevokeStaleDragGrants() []string {
	out := aclListing(applicationsDir)

	var revoked []string
	for _, user := range usersWithRights(out, aclRights) {
		if err := applyACL(applicationsDir, user, false); err == nil {
			revoked = append(revoked, user)
		}
	}
	return revoked
}

// aclEntry matches one numbered line of `ls -lde` output:
//
//	0: user:yesveer allow add_file,add_subdirectory
var aclEntry = regexp.MustCompile(`(?m)^\s*\d+:\s*user:(\S+)\s+allow\s+(\S+)\s*$`)

// usersWithRights names the accounts whose entry is exactly these rights.
func usersWithRights(listing, rights string) []string {
	var users []string
	for _, m := range aclEntry.FindAllStringSubmatch(listing, -1) {
		if sameRights(m[2], rights) {
			users = append(users, m[1])
		}
	}
	return users
}

// sameRights compares two comma-separated right lists as sets, because the
// order macOS prints them in is not promised.
func sameRights(a, b string) bool {
	left, right := strings.Split(a, ","), strings.Split(b, ",")
	if len(left) != len(right) {
		return false
	}
	have := make(map[string]bool, len(left))
	for _, r := range left {
		have[strings.TrimSpace(r)] = true
	}
	for _, r := range right {
		if !have[strings.TrimSpace(r)] {
			return false
		}
	}
	return true
}

// applyACL is the seam these are tested through. A test that really changed
// /Applications on the machine running it would be a test nobody dares run.
var applyACL = setACL

// setACL adds or removes the install window on /Applications.
func setACL(dir, user string, add bool) error {
	return setRights(dir, user, aclRights, add)
}

// setRights adds or removes one access-control entry.
//
// `chmod -a` with a rights list removes exactly those rights and leaves any
// others in the same entry alone — measured — so this never clobbers a grant
// somebody else made for another purpose.
func setRights(path, user, rights string, add bool) error {
	flag := "-a"
	if add {
		flag = "+a"
	}
	entry := fmt.Sprintf("user:%s allow %s", user, rights)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := runChmod(ctx, nil, flag, entry, path)
	if err == nil {
		return nil
	}

	// Refused. Asked once more from inside the console user's session.
	//
	// A LaunchDaemon runs as root with NO session attached, and that is the
	// case macOS is most willing to refuse outright — no prompt, no row in
	// System Settings, just EPERM. It fits what was measured here: root
	// refused an operation root would otherwise be allowed, and granting
	// App Management by hand changed nothing, which is what ruled the
	// obvious explanation out.
	//
	// `launchctl asuser` does not drop privileges. It stays root and
	// attaches the session, so this is the same operation asked in the one
	// context the first attempt could not supply. It costs one process, and
	// only after the first attempt has already failed.
	if uid := consoleUIDFn(); uid > 0 {
		if _, err2 := runChmod(ctx, []string{"/bin/launchctl", "asuser",
			strconv.Itoa(uid)}, flag, entry, path); err2 == nil {
			return nil
		}
	}

	return describeACLFailure(path, user, flag, err, string(out))
}

// runChmod is the seam these are tested through.
//
// A test that really set an access-control entry on /Applications would be
// changing the machine it runs on, and one that only read the source could
// not tell a call that is made from a call that is written down and never
// reached — which is the difference that matters here.
var runChmod = func(ctx context.Context, prefix []string, args ...string) ([]byte, error) {
	cmd := append(append([]string{}, prefix...), "/bin/chmod")
	cmd = append(cmd, args...)
	if len(prefix) == 0 {
		cmd = append([]string{"/bin/chmod"}, args...)
	}
	return exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
}

// consoleUIDFn is the seam for who is at the screen.
var consoleUIDFn = consoleUID

// consoleUID is the uid of whoever is at the screen, or 0.
func consoleUID() int {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return int(st.Uid)
}

// describeACLFailure turns a bare errno into something somebody can act on.
//
// "operation not permitted" on /Applications, as root, is not SIP — the
// directory carries no restricted flag and is absent from rootless.conf.
// Nobody reading the errno would guess what it is, and the fix is not
// anything in this product.
func describeACLFailure(path, user, flag string, err error, out string) error {
	detail := strings.TrimSpace(out)
	if strings.Contains(detail, "Operation not permitted") || errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("macOS refused an access-control entry on %s, from a "+
			"background service and from the user's own session. Granting the "+
			"agent App Management does not change this — it was tried. Until "+
			"something does, this Mac installs, updates and removes approved "+
			"software through the agent's menu bar item instead, and dragging "+
			"applications in or out of Applications will keep asking for an "+
			"administrator password: %w", path, err)
	}
	return fmt.Errorf("%s %s on %s: %w: %s", flag, user, path, err, detail)
}

// aclListing is `ls -lde` output for one path, or empty.
func aclListing(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ls", "-lde", path).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// IsInstalledPath reports whether a path names something already installed.
func IsInstalledPath(path string) bool {
	return filepath.Dir(filepath.Clean(path)) == applicationsDir
}

// InstalledPathFor is where an application of this name would live once it
// is installed, whether or not it is there yet.
//
// Policy rules written against a path mean the installed path. Judging a
// mounted image at its /Volumes path instead made those rules match only
// after the install had already happened.
func InstalledPathFor(name string) string {
	return filepath.Join(applicationsDir, name+".app")
}

// InstalledBundleFor is where an application from this installer would land,
// if it is already there.
func InstalledBundleFor(label string) string {
	candidate := filepath.Join(applicationsDir, label+".app")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}
