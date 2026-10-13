// Package tcc builds the messages shown when macOS refuses a privacy grant.
//
// It exists because those messages named a path that was WRITTEN INTO THEM.
// The helper moved — it now runs from inside the application bundle — and the
// messages went on telling people to grant /usr/local/bin/wxt-agent-session, a
// binary that was no longer running. Somebody following the instruction
// granted the wrong thing, saw no change, and had no way to tell why.
//
// A message about a process has to ask the process where it is.
package tcc

import (
	"fmt"
	"os"
	"path/filepath"
)

// selfPath is the running executable's resolved path.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

// DeniedMessage describes one refused grant and how to fix it.
//
// right is the name as System Settings shows it ("Accessibility", "Screen
// Recording"); what is the thing macOS would not let us do.
func DeniedMessage(right, what string) string {
	msg := fmt.Sprintf("macOS denied %s.", what)

	if p := selfPath(); p != "" {
		// Inside an application bundle macOS lists the BUNDLE, under the app's
		// name — so saying "switch on wxt-agent-session" would send somebody
		// looking for a row that does not exist.
		if app := enclosingApp(p); app != "" {
			msg += fmt.Sprintf(
				" Switch on %s in System Settings › Privacy & Security › %s.",
				filepath.Base(app), right)
		} else {
			msg += fmt.Sprintf(
				" Switch on %s in System Settings › Privacy & Security › %s.",
				p, right)
		}
		msg += fmt.Sprintf(" (the process asking is %s)", p)
	} else {
		msg += fmt.Sprintf(" Switch wxt-agent on in System Settings › Privacy & Security › %s.", right)
	}

	// macOS asks once. A dismissed prompt never comes back, and a grant is
	// recorded against the exact build it was given — so a row can be visibly
	// on and grant nothing to the binary now asking.
	msg += " macOS asks only once, so a dismissed prompt will not reappear — switch it on yourself." +
		" If it is already on, remove it with “−” and add it again: a grant made against an" +
		" earlier build no longer applies. The agent restarts itself once the grant is in place."

	return msg
}

// enclosingApp returns the .app bundle a path sits inside, or "".
//
// macOS attributes a privacy request from a binary inside a bundle to that
// bundle, so the bundle is what the person will see listed — not the binary.
func enclosingApp(path string) string {
	for dir := filepath.Dir(path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if filepath.Ext(dir) == ".app" {
			return dir
		}
	}
	return ""
}
