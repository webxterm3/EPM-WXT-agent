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

// ProductRowName is what System Settings calls this product.
//
// It comes from CFBundleName in the Info.plist embedded in this binary, which
// declares the application's bundle identifier — so macOS shows the product's
// name and icon rather than the helper's file name and a blank glyph. The two
// have to agree or this message points at a row that does not exist.
const ProductRowName = "wxt-agent"

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

	// ONE row, under the product's own name.
	//
	// This binary is signed with the application's bundle identifier, so macOS
	// sees the whole product as a single code identity and lists it once, with
	// the product icon — rather than once per binary per path, under bare file
	// names with a blank icon. Naming anything else here sends somebody to a
	// row that grants nothing.
	msg += fmt.Sprintf(
		" Switch on %s — the row with the product icon — in"+
			" System Settings › Privacy & Security › %s.", ProductRowName, right)

	msg += " That one row covers the whole product; there is nothing else to add."

	// People arriving at this message have usually already added two or three
	// binaries by hand looking for the one that worked. Those rows are inert
	// and they make the list unreadable, so say to remove them.
	msg += " Any rows with a blank icon (wxt-agent-session, wxt-agent-menubar) are left" +
		" over from an older version, grant nothing, and can be removed with “−”."

	if p := selfPath(); p != "" {
		msg += fmt.Sprintf(" (the process asking is %s)", p)
	}

	// macOS asks once, and a dismissed prompt never comes back.
	msg += " macOS asks only once, so a dismissed prompt will not reappear — switch it on yourself." +
		" The agent restarts itself once the grant is in place."

	return msg
}
