// Command wxt-agent-menubar shows the agent's state in the system's own status
// area — the macOS menu bar, the Windows notification area.
//
// A separate program from the agent, and a separate per-user service, because
// the agent runs as root/SYSTEM with no desktop session and cannot draw
// anything a person will see. Anything the logged-in user sees has to run as
// them.
//
// It is deliberately a reader. It shows what the agent publishes and runs the
// agent's own commands; it holds no state and makes no decisions, so a bug
// here can confuse somebody but cannot break remote control.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
)

// version is set at build time.
var version = "dev"

// pollInterval is how often the status file is re-read.
//
// The file is a few hundred bytes on local disk, so this is cheap; the limit
// is how fast somebody expects the icon to turn after a connection drops.
const pollInterval = 5 * time.Second

// staleAfter is when a published status stops being believed.
//
// The agent refreshes every 15s, so three missed refreshes means it is not
// running — and a stopped agent must show as disconnected rather than leaving
// the last thing it said on screen for ever.
const staleAfter = 50 * time.Second

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("wxt-agent-menubar %s\n", version)
		return
	}
	// --blocked is how a user finds out their organisation stopped a program.
	//
	// Windows runs this binary IN PLACE OF a blocked application, passing the
	// original command line along, because that is what an Image File
	// Execution Options entry does. It is this binary rather than the agent
	// for one reason: this one is built for the GUI subsystem, so the message
	// appears without a console window flashing up first — and a blocked
	// launch with no explanation is indistinguishable from broken software.
	if len(os.Args) > 1 && os.Args[1] == "--blocked" {
		showBlockedNotice(blockedProgramName(os.Args[2:]))
		return
	}
	run()
}

// blockedProgramName is the program the user tried to start.
//
// The command line arrives exactly as it was typed or launched, so the first
// argument is the executable — quoted when it has spaces in it, which on
// Windows is most of the time.
func blockedProgramName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	name := strings.Trim(args[0], `"`)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// currentState is read by the Cocoa side on every tick.
func currentState() (connected bool, title, detail string) {
	st, ok := agentstatus.Read()
	switch {
	case !ok:
		return false, "wxt-agent: not installed", "The agent has not reported yet."
	case st.Stale(staleAfter):
		return false, "wxt-agent: not running",
			fmt.Sprintf("Last reported %s ago.", time.Since(st.UpdatedAt).Round(time.Second))
	case st.Connected:
		return true, "wxt-agent: connected",
			fmt.Sprintf("%s · %s", nonEmpty(st.Machine, "this Mac"), nonEmpty(st.Server, "server unknown"))
	default:
		d := "Not connected to the server."
		if st.LastError != "" {
			d = st.LastError
		}
		return false, "wxt-agent: not connected", d
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// showStatus reports what the agent last published, in full.
func showStatus() {
	st, ok := agentstatus.Read()
	if !ok {
		showText("Agent status", "The agent has not reported yet.\n\nIt may not be installed, or it may have only just started.")
		return
	}

	state := "not connected"
	if st.Connected {
		state = "connected"
	}
	if st.Stale(staleAfter) {
		state = "not running"
	}

	body := fmt.Sprintf(
		"State:     %s\nMachine:   %s\nAgent ID:  %s\nServer:    %s\nVersion:   %s\nReported:  %s ago",
		state,
		nonEmpty(st.Machine, "—"),
		nonEmpty(st.AgentID, "—"),
		nonEmpty(st.Server, "—"),
		nonEmpty(st.Version, "—"),
		time.Since(st.UpdatedAt).Round(time.Second),
	)
	if st.LastError != "" {
		body += "\n\nLast error:\n" + st.LastError
	}
	showText("Agent status", body)
}
