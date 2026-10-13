//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/Yesveer/wxt-agent/internal/agent"
)

func uninstallPlan(keepConfig bool) []string {
	plan := []string{
		"the scheduled task (" + agent.WindowsTaskName + ")",
		winInstalledExe + " and the session helper",
		"the Programs and Features entry",
	}
	if !keepConfig {
		plan = append(plan, winConfigDir+" (configuration, certificates and logs)")
	}
	return plan
}

func uninstallAgent(keepConfig bool) []string {
	var problems []string

	// The task goes first. Deleting the files while it is registered leaves
	// Windows launching a binary that is no longer there at every startup,
	// forever, and leaves a running agent holding the files being removed.
	_ = exec.Command("schtasks", "/end", "/tn", agent.WindowsTaskName).Run()
	if out, err := exec.Command("schtasks", "/delete", "/tn", agent.WindowsTaskName, "/f").CombinedOutput(); err != nil {
		// "cannot find the file specified" is the normal second-run answer.
		if !containsAny(string(out), "cannot find", "does not exist") {
			problems = append(problems, fmt.Sprintf("scheduled task: %v (%s)", err, string(out)))
		}
	}

	// The running processes, in case the task was ended but something lingers.
	_ = exec.Command("taskkill", "/f", "/im", "wxt-agent-session.exe").Run()

	unregisterFromAddRemovePrograms()

	remove := func(path string) {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
		}
	}

	// Not the running binary: this process IS winInstalledExe when Control
	// Panel invoked it, and Windows will not delete a file that is open. It is
	// scheduled for removal on the next boot instead.
	remove(winConfigDir + `\` + "wxt-agent-session.exe")
	remove(winConfigDir + `\` + "wxt-agent.ico")
	if !keepConfig {
		remove(winConfigDir)
	}
	if err := markForDeleteOnReboot(winInstalledExe); err != nil {
		problems = append(problems, fmt.Sprintf("%s will be removed at the next restart: %v", winInstalledExe, err))
	}

	return problems
}

func containsAny(s string, needles ...string) bool {
	lower := strings.ToLower(s)
	for _, n := range needles {
		if n != "" && strings.Contains(lower, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// markForDeleteOnReboot asks Windows to remove a file at the next startup.
//
// Needed because Control Panel runs the uninstaller by running the very binary
// being uninstalled, and Windows refuses to delete an open executable. The
// alternative — a temporary copy that deletes the original and then itself —
// leaves a stray binary behind whenever the machine is powered off mid-way.
func markForDeleteOnReboot(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// MOVEFILE_DELAY_UNTIL_REBOOT with a nil destination means "delete".
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

func printPostUninstallNotes() {
	fmt.Println()
	fmt.Println("The agent binary is removed at the next restart: Windows will not")
	fmt.Println("delete a program while it is the one doing the uninstalling.")
}
