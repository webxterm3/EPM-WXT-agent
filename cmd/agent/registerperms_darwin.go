//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// macAppBundleID is the one code identity the whole product presents to macOS.
//
// The application bundle declares it, and the session helper — the only binary
// that ever asks for a privacy grant — is signed with it too. That is what
// makes System Settings show a single row, named and iconed like the product,
// instead of one nameless row per binary per path.
//
// It must match MACOS_APP_ID in the Makefile and the CFBundleIdentifier in
// build/macos/session-helper-info.plist; the build fails if the helper does
// not carry it.
const macAppBundleID = "io.coredge.epm.app"

// registerPermissionRows makes the agent's rows appear in System Settings, so
// that granting them is a switch to flip rather than a hunt for a binary.
//
// macOS lists a program under Accessibility or Screen Recording only once that
// program has ASKED for the right. Until then the list simply does not mention
// it, and the only way in is "+" followed by navigating to a binary inside an
// application bundle — which is hidden from the file chooser by default.
// People were doing that by hand, for three binaries, after every install.
//
// Asking is therefore done here, at the end of enrolment, while somebody is
// sitting in front of the machine and expecting to be asked. The system prompt
// appears, and whether they accept it or dismiss it the row is now there to be
// switched on.
//
// ONE binary is registered, not three. Only the session helper ever requests
// a privacy grant: the agent shells out to it and the menu bar item only reads
// a status file. Rows for the other two would be rows that grant nothing,
// which is worse than no row at all — somebody switches them on, nothing
// changes, and now they distrust the ones that matter.
func registerPermissionRows() {
	helper := bundledHelperPath()
	if helper == "" {
		fmt.Println("  (skipped — the session helper is not installed)")
		return
	}

	uid, err := consoleUserID()
	if err != nil {
		fmt.Println("  (skipped — nobody is logged in at the screen)")
		fmt.Println("  Run `sudo wxt-agent check-permissions` once somebody is.")
		return
	}

	if _, ok := askForPermissions(helper, uid); ok {
		fmt.Println("  ✓ Screen Recording and Accessibility are already granted")
		return
	}

	// Denied — and NOTHING is reset here.
	//
	// This used to call tccutil on the product's own identity whenever the
	// answer was anything but "granted", on the theory that a denial might be
	// a stale row worth clearing. It cannot tell a stale row from a brand new
	// install from a user who has simply not switched it on yet — so in
	// practice it threw away the working grant on every single run of
	// configure. Somebody would grant the permission, re-enrol, and find it
	// gone, which is precisely the symptom this code was written to fix.
	//
	// Resetting is now only ever done when a human asks for it:
	// `wxt-agent repair-permissions`.
	fmt.Println()
	fmt.Println("  Switch ONE row on, in each of these two panes:")
	fmt.Println()
	fmt.Println("    System Settings › Privacy & Security › Accessibility")
	fmt.Println("    System Settings › Privacy & Security › Screen Recording")
	fmt.Println()
	fmt.Println("  The row is called \"wxt-agent\" and carries the product icon.")
	fmt.Println("  It covers the whole product — there is nothing else to add.")
	fmt.Println()
	fmt.Println("  A row that is already switched on but still does not work is a")
	fmt.Println("  grant recorded against an earlier build. Clear it with:")
	fmt.Println("      sudo wxt-agent repair-permissions")
}

// askForPermissions runs the helper the way a real session runs it and reports
// whether both grants apply.
//
// launchctl asuser, exactly as the agent launches it: a grant is evaluated for
// the process as it is actually started, so asking any other way — as root,
// outside the user's GUI session — answers about a different context to the
// one that will need the right.
func askForPermissions(helper string, uid int) (string, bool) {
	cmd := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(uid),
		helper, "--check-permissions")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// clearStalePermissionRows removes this product's own privacy entries.
//
// Scoped to our bundle identifier. `tccutil reset Accessibility` with no
// identifier resets EVERY application on the machine, which is somebody else's
// afternoon.
//
// This only became possible when the helper started claiming the application's
// bundle identifier. tccutil resolves an identifier through LaunchServices, so
// the identifiers the binaries used to carry — io.coredge.epm.wxt-agent-session
// and friends — were rejected with "No such bundle identifier" every single
// time. The uninstaller had been calling it for months and silently clearing
// nothing, which is why a reinstall never started clean.
func clearStalePermissionRows(uid int) bool {
	cleared := false
	for _, service := range []string{"Accessibility", "ScreenCapture"} {
		// Both databases. Accessibility lives in the system one and
		// ScreenCapture in the console user's, and which is which is not
		// something to rely on — asking twice is cheap and covers both.
		if runTCCUtil(service, 0) {
			cleared = true
		}
		if runTCCUtil(service, uid) {
			cleared = true
		}
	}
	return cleared
}

// runTCCUtil resets one service for this product, as root when uid is 0 and as
// the console user otherwise. It reports whether anything was actually reset.
func runTCCUtil(service string, uid int) bool {
	args := []string{"reset", service, macAppBundleID}
	cmd := exec.Command("tccutil", args...)
	if uid != 0 {
		cmd = exec.Command("/bin/launchctl",
			append([]string{"asuser", strconv.Itoa(uid), "tccutil"}, args...)...)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// tccutil exits 0 even when it did nothing, so the message is the only
	// signal that a row was really there.
	return strings.Contains(string(out), "Successfully reset")
}

// bundledHelperPath is the helper copy that actually runs.
//
// The same order the agent uses — the bundle first. Registering the
// /usr/local/bin copy would put the wrong binary in System Settings: somebody
// switches on a row for a program nothing launches, and every session is still
// refused with the switch visibly on.
func bundledHelperPath() string {
	for _, candidate := range []string{
		macAppBundle + "/Contents/MacOS/wxt-agent-session",
		filepath.Join(macInstallDir, "wxt-agent-session"),
	} {
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}
	return ""
}

// waitForSettingsPane gives the prompt a moment to appear before enrolment's
// closing lines scroll past it.
//
// Not a fix for anything, just ordering: the system prompt is asynchronous,
// and output racing it reads as if the prompt belongs to whatever came next.
func waitForSettingsPane() { time.Sleep(500 * time.Millisecond) }
