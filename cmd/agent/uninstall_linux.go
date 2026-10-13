//go:build !windows && !darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
)

func uninstallPlan(keepConfig bool) []string {
	plan := []string{
		"the systemd service (wxt-agent)",
		"/usr/local/bin/wxt-agent",
	}
	if !keepConfig {
		plan = append(plan, "/etc/vsay (configuration and certificates)")
	}
	return plan
}

func uninstallAgent(keepConfig bool) []string {
	var problems []string

	_ = exec.Command("systemctl", "stop", "wxt-agent").Run()
	_ = exec.Command("systemctl", "disable", "wxt-agent").Run()

	remove := func(path string) {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
		}
	}

	remove("/etc/systemd/system/wxt-agent.service")
	remove("/usr/local/bin/wxt-agent")
	if !keepConfig {
		remove("/etc/vsay")
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()

	return problems
}

func printPostUninstallNotes() {}
