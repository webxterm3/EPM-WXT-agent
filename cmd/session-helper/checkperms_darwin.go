//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Yesveer/wxt-agent/internal/remotecontrol/capture"
	"github.com/Yesveer/wxt-agent/internal/remotecontrol/input"
)

// reportPermissions prints what this process can actually do. Exit code 0 when
// everything needed is granted, 1 otherwise.
//
// Every line is about THIS running process, because "did I grant it?" cannot
// be answered from System Settings: a grant is tied to a code signature, so a
// rebuilt binary leaves the switch on and the permission off — which looks
// exactly like a broken product.
func reportPermissions() int {
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	fmt.Println("wxt-agent-session permission check")
	fmt.Println()
	fmt.Println("  binary:", exe)
	fmt.Println("  uid:   ", os.Getuid())
	fmt.Println()

	// The code identity, because that is what the grant is recorded against.
	// A grant made before this binary was rebuilt no longer applies to it, and
	// this is how somebody sees that for themselves.
	if out, err := exec.Command("/usr/bin/codesign", "-d", "--verbose=2", exe).CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Identifier=") || strings.HasPrefix(line, "Signature") {
				fmt.Println("  " + line)
			}
		}
		fmt.Println()
	}

	// ASK, do not merely check.
	//
	// macOS lists a binary under Accessibility or Screen Recording only once
	// that binary has REQUESTED the right; checking registers nothing. This
	// command exists partly so somebody can make the rows appear, and it was
	// exiting before the request was ever made — so the honest answer to "why
	// is wxt-agent not in the list?" was "because nothing has asked yet".
	//
	// Requesting also answers the question, so nothing is checked twice.
	accessibility := input.RequestAccessibility()
	screen := capture.RequestScreenRecording()

	report("Accessibility    (move the pointer, type)", accessibility)
	report("Screen Recording (see the screen)        ", screen)

	if accessibility && screen {
		fmt.Println()
		fmt.Println("Both grants apply to this binary. Remote control will work.")
		return 0
	}

	fmt.Println()
	fmt.Println("Switch this on in whichever is missing:")
	fmt.Println("   ", exe)
	fmt.Println()
	fmt.Println("System Settings › Privacy & Security › Accessibility")
	fmt.Println("System Settings › Privacy & Security › Screen Recording")
	fmt.Println()
	fmt.Println("The entry is listed there once the agent has tried a session. macOS asks")
	fmt.Println("only once, so a dismissed prompt will not come back — switch it on yourself.")
	fmt.Println("If it is already ON, remove it with “−” and add it again: a grant made")
	fmt.Println("against an earlier build of this binary no longer applies to it.")
	return 1
}

func report(name string, ok bool) {
	mark := "✗ denied"
	if ok {
		mark = "✓ granted"
	}
	fmt.Printf("  %s  %s\n", name, mark)
}
