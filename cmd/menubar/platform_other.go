//go:build !darwin && !windows

package main

import (
	"fmt"
	"os/exec"
)

// There is no status area to draw in here.
//
// The program still builds and still runs, and says why rather than failing to
// compile: a command that exists on two platforms and vanishes on the third is
// a build break waiting for whoever next runs `go build ./...`.

const agentPath = "/usr/local/bin/wxt-agent"

func openLogs() {
	_ = exec.Command("xdg-open", "/var/log/vsay/agent.log").Start()
}

func showText(title, body string) {
	fmt.Printf("%s\n\n%s\n", title, body)
}

// confirmText cannot ask anybody anything here, so it answers no.
//
// No is the answer that does nothing. Raising an approval request on a
// platform with no way to show the question would send an administrator a
// request nobody made.
func confirmText(title, body, okTitle, cancelTitle string) bool {
	fmt.Printf("%s\n\n%s\n", title, body)
	return false
}

func run() {
	fmt.Println("There is no system status area on this platform.")
	fmt.Println("Use `wxt-agent check-permissions` and /var/log/vsay/agent.log instead.")
}

// showBlockedNotice is unused on this platform; application control targets
// Windows and macOS.
func showBlockedNotice(program string) {
	if program == "" {
		program = "that application"
	}
	showText("Blocked by your organisation",
		program+" has been blocked by your organisation's application policy.")
}

// checkPermissions runs the agent's own diagnostic and shows its output.
//
// No privacy database on this platform; the agent's own output is shown as-is.
func checkPermissions() {
	out, err := exec.Command(agentPath, "check-permissions").CombinedOutput()
	text := string(out)
	if err != nil && text == "" {
		text = fmt.Sprintf("Could not run the check: %v", err)
	}
	showText("Permissions", text)
}

// uninstallAgent is macOS and Windows only; there is no status area here to
// offer it from.
func uninstallAgent() {
	showText("Uninstall", "Run `sudo wxt-agent uninstall` in a terminal.")
}
