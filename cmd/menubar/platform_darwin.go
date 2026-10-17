//go:build darwin

package main

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
)

// Cocoa insists on the main thread.
func init() { runtime.LockOSThread() }

// agentPath is the installed agent, which this program shells out to rather
// than reimplementing. "Check permissions" here and `wxt-agent
// check-permissions` in a terminal must not be two different checks.
const agentPath = "/usr/local/bin/wxt-agent"

// openLogs shows the agent log in Console, which is where somebody who does
// not open a terminal reads logs on a Mac.
func openLogs() {
	_ = exec.Command("/usr/bin/open", "-a", "Console", "/var/log/vsay/agent.log").Start()
}

// run installs the status item and runs the Cocoa event loop. It does not
// return.
func run() { runMenuBar() }

// showBlockedNotice exists for symmetry with Windows and is not reached on
// macOS: launch prevention here withholds the execute bit from the
// application's own binary, so the launch fails in Finder with the system's
// own message and nothing of ours is started in its place.
func showBlockedNotice(program string) {
	if program == "" {
		program = "that application"
	}
	showText("Blocked by your organisation",
		program+" has been blocked by your organisation's application policy.")
}

// checkPermissions reports what the agent last recorded, and offers to open
// the Settings pane. It does NOT run the permission check itself.
//
// This is the most surprising constraint in the product, so it is written down
// here rather than learned again: macOS records a privacy grant against the
// RESPONSIBLE process — the topmost launchd-started ancestor of whoever calls
// the API — not against the caller.
//
// This menu item used to run `wxt-agent check-permissions`, which spawns the
// session helper, which asks macOS for Accessibility and Screen Recording.
// launchctl asuser does not break that chain; man launchctl is explicit that
// it "does not move the target process into the target user's bootstrap". So
// the ancestor at the head of the chain was THIS program, and the result was a
// row in System Settings called "wxt-agent-menubar" — created by a binary that
// contains no privacy code at all (nm -u finds no TCC symbols in it), granting
// nothing to anybody, and impossible to remove programmatically.
//
// So it no longer asks. Asking is the agent's job, from the agent, in the
// context sessions actually run in.
func checkPermissions() {
	st, ok := agentstatus.Read()
	switch {
	case !ok:
		showText("Permissions",
			"The agent has not reported yet.\n\n"+
				"Open Terminal and run:\n    sudo wxt-agent check-permissions")
	case st.PermissionsOK:
		showText("Permissions",
			"Screen Recording and Accessibility are granted.\n\nRemote control will work.")
	default:
		detail := st.PermissionNote
		if detail == "" {
			detail = "Remote control needs Screen Recording and Accessibility."
		}
		showText("Permissions", detail+"\n\n"+
			"Switch on the \"wxt-agent\" row — the one with the product icon — in\n"+
			"System Settings › Privacy & Security › Accessibility\n"+
			"System Settings › Privacy & Security › Screen Recording\n\n"+
			"That one row covers the whole product.")
		openPrivacySettings()
	}
}

// openPrivacySettings takes the user straight to the Accessibility pane.
//
// A URL handed to `open`, which is LaunchServices opening System Settings — no
// privacy-gated API is touched, so this program never becomes the responsible
// process for a request and never appears in the list it is pointing at.
func openPrivacySettings() {
	_ = exec.Command("/usr/bin/open",
		"x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility").Start()
}

// uninstallAgent removes the product from this Mac.
//
// It is on the menu because there was nowhere else to find it. The only
// uninstall route was to open the application, press "Check Permissions", and
// find a button at the bottom of the dialog that appeared — and the
// application itself cannot simply be dragged to the Trash, because the daemon
// runs from inside it and macOS will not move a bundle something is running
// from.
//
// The work is delegated to `wxt-agent uninstall`, the same command the
// installer app and the terminal use, so there is one description of what
// "installed" means rather than three that drift.
func uninstallAgent() {
	if !confirmUninstall() {
		return
	}

	// osascript's "with administrator privileges" puts up the system's own
	// password panel. The menu bar item runs as the logged-in user and the
	// daemon it is removing runs as root, so something has to ask.
	script := `do shell script "` + agentPath + ` uninstall --yes" with administrator privileges`
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()

	text := strings.TrimSpace(string(out))
	switch {
	case err != nil && strings.Contains(text, "User canceled"):
		return
	case err != nil:
		showText("Uninstall did not finish",
			"Something was left behind:\n\n"+tail(text, 700)+
				"\n\nRunning this in Terminal usually clears it:\n    sudo "+agentPath+" uninstall")
	default:
		showText("wxt-agent removed",
			"The agent, its service and its configuration are gone.\n\n"+
				"Any application it had blocked has been put back.\n\n"+
				"This menu bar icon disappears when you log out, or you can "+
				"choose Hide Menu Bar Icon now.")
	}
}

// confirmUninstall asks first. Removing a management agent is not something to
// do on a mis-click, and it takes the machine out of the fleet.
func confirmUninstall() bool {
	const script = `display dialog "Remove wxt-agent from this Mac?

This stops the agent, removes its service, its configuration and its logs, and restores any application it had blocked.

The machine stays listed in the portal until an administrator removes it there." with title "Uninstall wxt-agent" buttons {"Cancel", "Uninstall"} default button "Cancel" with icon caution`

	out, err := exec.Command("/usr/bin/osascript", "-e", script,
		"-e", "button returned of result").Output()
	return err == nil && strings.TrimSpace(string(out)) == "Uninstall"
}

// tail keeps the last n characters, which is where a command's real error is.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
