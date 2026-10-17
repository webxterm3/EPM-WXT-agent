//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Yesveer/wxt-agent/internal/agent"
)

// macAppBundle is the visible face of the agent in /Applications.
//
// The agent itself is a daemon in /usr/local/bin and would otherwise appear
// nowhere a person ever looks. A bundle here is how macOS answers "is this
// installed, and how do I get rid of it".
const macAppBundle = "/Applications/wxt-agent.app"

// legacyAppBundles are names earlier builds installed under.
//
// They must be removed too. An uninstaller that only knows the CURRENT name
// leaves every previous one behind, and what somebody then sees in
// Applications is a stale bundle with a stale icon — which reads as "the
// uninstall did not work" and "the new icon never arrived", because from
// Finder those are the same thing.
var legacyAppBundles = []string{
	"/Applications/EPM Agent.app",
	"/Applications/Install EPM Agent.app",
	"/Applications/Uninstall EPM Agent.app",
}

func uninstallPlan(keepConfig bool) []string {
	plan := []string{
		"the background service (" + agent.LaunchDaemonLabel + ")",
		"/usr/local/bin/wxt-agent, wxt-agent-menubar and the menu bar icon",
		macAppBundle + " (and any earlier name it was installed under)",
	}
	if !keepConfig {
		plan = append(plan,
			"/etc/vsay (configuration and certificates)",
			"/var/log/vsay (logs)",
			"its rows in Privacy & Security (Accessibility, Screen Recording)")
	}
	return plan
}

// tccIdentities are the names macOS has recorded permission decisions under.
//
// ONE entry, and it is the application's bundle identifier, because tccutil
// resolves what it is given through LaunchServices. A code-signing identifier
// that belongs to no registered bundle — io.coredge.epm.wxt-agent-session, as
// the helper used to carry — is rejected with "No such bundle identifier"
// every time. This list had that spelling in it, the error was swallowed as
// "a row that was never there", and so an uninstall cleared nothing at all
// while reporting success. A reinstall then inherited stale rows that were
// switched on and granted nothing.
//
// Rows left by versions before the helper shared the app's identity are keyed
// by FILE PATH and cannot be reached by tccutil at all. They are inert, and
// the uninstaller says so rather than pretending to have removed them.
var tccIdentities = []string{"io.coredge.epm.app"}

// tccServices are the two permissions remote control needs.
var tccServices = []string{"Accessibility", "ScreenCapture"}

// purgePermissions removes this product's rows from the privacy database.
//
// Scoped to our own bundle identifiers — `tccutil reset Accessibility` with no
// identifier resets EVERY application on the machine, which is somebody else's
// afternoon.
//
// Worth doing on uninstall because a stale row is actively misleading: it
// stays switched on, grants nothing to a rebuilt binary, and makes a fresh
// install look broken in exactly the way that is hardest to diagnose.
func purgePermissions() (cleared int, problems []string) {
	for _, service := range tccServices {
		for _, id := range tccIdentities {
			out, err := exec.Command("tccutil", "reset", service, id).CombinedOutput()
			if err == nil {
				// tccutil exits 0 whether or not a row was there, so its own
				// message is the only evidence that anything happened.
				if strings.Contains(string(out), "Successfully reset") {
					cleared++
				}
				continue
			}
			// "No such bundle identifier" means the product was never granted
			// this right, which is not a failure. Anything else is.
			if !strings.Contains(string(out), "No such") {
				problems = append(problems, fmt.Sprintf("%s for %s: %v", service, id, err))
			}
		}
	}
	return cleared, problems
}

func uninstallAgent(keepConfig bool) []string {
	var problems []string

	// Stopped first: removing the binary underneath a running daemon leaves
	// launchd restarting something that is no longer there.
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+agent.LaunchDaemonLabel).Run()

	// The menu bar item too, or its icon sits there after the agent is gone,
	// pointing at a binary that no longer exists.
	if uid := os.Getenv("SUDO_UID"); uid != "" {
		_ = exec.Command("/bin/launchctl", "bootout", "gui/"+uid+"/"+agent.LaunchAgentLabel).Run()
	}

	// The privacy rows go FIRST, while the bundle is still on disk.
	//
	// tccutil resolves the identifier it is given through LaunchServices, and
	// io.coredge.epm.app only resolves while /Applications/wxt-agent.app
	// exists. This ran at the end, twelve lines after the bundle was deleted,
	// so every uninstall reported success and cleared nothing — which is why a
	// reinstall never started from a clean grant.
	cleared := 0
	if !keepConfig {
		var purgeProblems []string
		cleared, purgeProblems = purgePermissions()
		problems = append(problems, purgeProblems...)
	}

	remove := func(path string) {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
		}
	}

	remove("/Library/LaunchDaemons/" + agent.LaunchDaemonLabel + ".plist")
	remove("/usr/local/bin/wxt-agent")
	remove("/usr/local/bin/wxt-agent-menubar")
	remove("/Library/LaunchAgents/" + agent.LaunchAgentLabel + ".plist")
	remove("/usr/local/bin/wxt-agent-session")
	remove(macAppBundle)
	for _, legacy := range legacyAppBundles {
		remove(legacy)
	}

	if !keepConfig {
		remove("/etc/vsay")
		remove("/var/log/vsay")
	}
	lastPurgeCleared = cleared
	return problems
}

// lastPurgeCleared is how many privacy rows the purge actually removed, read
// by the closing notes so they can report what happened instead of asserting
// it. Package-level because uninstallAgent's signature is shared with the
// other platforms.
var lastPurgeCleared int

func printPostUninstallNotes() {
	fmt.Println()
	// Reported, not asserted. This used to claim the rows had been removed
	// whatever happened — including when tccutil had cleared nothing at all,
	// which was every single time, because the bundle it needed had already
	// been deleted.
	if lastPurgeCleared > 0 {
		fmt.Printf("Removed %d Privacy & Security row(s) for this product, so a fresh\n", lastPurgeCleared)
		fmt.Println("install starts from a clean grant rather than inheriting one that was")
		fmt.Println("recorded against a different build.")
		return
	}
	fmt.Println("No Privacy & Security rows needed removing.")
	fmt.Println()
	fmt.Println("If System Settings still lists a wxt-agent row with a BLANK icon, it")
	fmt.Println("belongs to a file path rather than to the application, and macOS gives")
	fmt.Println("no way for a program to remove it. Select it and press \"−\".")
}
