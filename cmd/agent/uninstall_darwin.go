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
		"/usr/local/bin/wxt-agent and wxt-agent-session",
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
// Both the bundle and the bare helper identifier: the helper has run from
// inside the application bundle and, in older installs, from /usr/local/bin —
// which macOS treats as two different programs with two separate rows.
var tccIdentities = []string{
	"io.coredge.epm.app",
	"io.coredge.epm.wxt-agent-session",
}

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
func purgePermissions() []string {
	var problems []string
	for _, service := range tccServices {
		for _, id := range tccIdentities {
			if out, err := exec.Command("tccutil", "reset", service, id).CombinedOutput(); err != nil {
				// A row that was never there is not a failure.
				if !strings.Contains(string(out), "No such") {
					problems = append(problems, fmt.Sprintf("%s for %s: %v", service, id, err))
				}
			}
		}
	}
	return problems
}

func uninstallAgent(keepConfig bool) []string {
	var problems []string

	// Stopped first: removing the binary underneath a running daemon leaves
	// launchd restarting something that is no longer there.
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+agent.LaunchDaemonLabel).Run()

	remove := func(path string) {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
		}
	}

	remove("/Library/LaunchDaemons/" + agent.LaunchDaemonLabel + ".plist")
	remove("/usr/local/bin/wxt-agent")
	remove("/usr/local/bin/wxt-agent-session")
	remove(macAppBundle)
	for _, legacy := range legacyAppBundles {
		remove(legacy)
	}

	if !keepConfig {
		remove("/etc/vsay")
		remove("/var/log/vsay")

		// The privacy rows go with a full removal. Keeping the configuration
		// means keeping the enrolment for a reinstall, and the permission the
		// person already gave belongs with it.
		problems = append(problems, purgePermissions()...)
	}
	return problems
}

func printPostUninstallNotes() {
	fmt.Println()
	fmt.Println("The Privacy & Security rows for this product have been removed too,")
	fmt.Println("so a fresh install starts from a clean grant rather than inheriting")
	fmt.Println("one that was recorded against a different build.")
}
