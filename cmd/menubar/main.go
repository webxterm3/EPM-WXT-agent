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
	"errors"
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
// is how fast somebody expects the icon to turn after a connection drops —
// and, since the same tick is what raises the install-approval dialog, how
// long somebody stands in front of a mounted disk image with no idea that
// dragging it across is going to be refused.
const pollInterval = 3 * time.Second

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
//
// Three strings rather than one: the headline answer, the machine this is,
// and where its policy stands. They are separate rows because they go stale at
// completely different rates — the connection changes by the second, the
// policy by the week — and one line mixing them would make the fresher fact
// vouch for the older one.
func currentState() (connected bool, title, detail, sync string) {
	st, ok := agentstatus.Read()
	switch {
	case !ok:
		return false, "wxt-agent not installed", "The agent has not reported yet.", policyLine(st, false)
	case st.Stale(staleAfter):
		return false, "wxt-agent not running",
			fmt.Sprintf("Last reported %s ago", shortDuration(time.Since(st.UpdatedAt))),
			policyLine(st, false)
	case st.Connected:
		return true, "wxt-agent connected" + connectedFor(st),
			fmt.Sprintf("%s · %s", nonEmpty(st.Machine, "this Mac"), nonEmpty(st.Server, "server unknown")),
			policyLine(st, true)
	default:
		d := "Not connected to the server"
		if st.LastError != "" {
			d = st.LastError
		}
		return false, "wxt-agent not connected", d, policyLine(st, false)
	}
}

// connectedFor says how long the CURRENT connection has lasted.
//
// Empty when the agent has not published a start time — an agent from before
// that field existed, which reports connected without saying since when.
// Saying "connected · 0s" there would be a worse answer than saying nothing.
func connectedFor(st agentstatus.Status) string {
	if st.ConnectedSince.IsZero() {
		return ""
	}
	d := time.Since(st.ConnectedSince)
	if d < 0 {
		// The agent's clock ran ahead of this one, or the file was written
		// during a clock change. A negative age is worse than no age.
		return ""
	}
	return " · " + shortDuration(d)
}

// policyLine reports when policy last arrived and what it contained.
//
// Deliberately distinct from the connection: a machine can be connected for a
// week and hold a policy from a month ago, and the menu's job is to let
// somebody see that without opening the portal.
func policyLine(st agentstatus.Status, connected bool) string {
	if st.PolicySyncedAt.IsZero() {
		if connected {
			return "Policy not synced yet"
		}
		return "Policy never synced"
	}

	when := shortDuration(time.Since(st.PolicySyncedAt))
	line := "Policy synced " + when + " ago"

	switch {
	case st.PolicyRules == 1:
		line += " · 1 rule"
	case st.PolicyRules > 1:
		line += fmt.Sprintf(" · %d rules", st.PolicyRules)
	default:
		// Zero rules is a real and confusing state — a policy did arrive,
		// and it says nothing about anything. Named rather than left as a
		// missing clause that reads like a rendering fault.
		line += " · no rules"
	}
	if st.PolicyMode != "" {
		line += ", " + st.PolicyMode
	}
	return line
}

// shortDuration formats an age the way somebody reads a status line: the
// largest unit that still carries information, not a full breakdown.
//
// time.Duration's own String gives "2h14m9.3s", which is precise and unusable
// at a glance — and the glance is the entire purpose of this menu.
func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) - days*24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %dh", days, h)
	}
}

// requestSync asks the agent to fetch policy now.
//
// The menu bar cannot fetch anything itself: it runs as the logged-in user and
// the connection belongs to the root daemon. It writes a request the agent
// picks up within a second.
//
// It reports what it DID — asked — rather than what it hopes will happen. The
// agent may be offline, and this program has no way to find out; claiming
// "synced" here would be a guess presented as a fact. The sync line above
// updates on its own when policy actually lands, which is the real answer.
func requestSync() {
	if err := agentstatus.RequestSync(); err != nil {
		// Two different problems, and they send somebody to different places.
		// The first version reported both as "the agent is not installed",
		// which was wrong in the common case and unhelpful in the other.
		if errors.Is(err, agentstatus.ErrSyncUnavailable) {
			showText("The agent is not running",
				"Sync Now needs the agent, and it has not started on this machine.\n\n"+
					"Check \"Agent Status…\" above. If it says the agent is not running, "+
					"the policy on this machine is whatever it last received.")
			return
		}
		showText("Could not ask for a sync",
			"The request could not be written:\n\n"+err.Error()+
				"\n\nThis is unexpected — the agent prepares that file when it starts. "+
				"The agent log will say whether it could.")
		return
	}
	showText("Sync requested",
		"The agent has been asked to fetch the latest policy.\n\n"+
			"If it is connected, the \"Policy synced\" line updates within a few seconds. "+
			"If it is offline, the request is dropped and policy arrives when it reconnects.")
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

	connFor := "—"
	if d := connectedFor(st); d != "" {
		connFor = strings.TrimPrefix(d, " · ")
	}

	synced := "never"
	if !st.PolicySyncedAt.IsZero() {
		synced = fmt.Sprintf("%s ago (%s)",
			shortDuration(time.Since(st.PolicySyncedAt)),
			st.PolicySyncedAt.Local().Format("2 Jan 15:04"))
	}

	body := fmt.Sprintf(
		"State:      %s\nConnected:  %s\nMachine:    %s\nAgent ID:   %s\nServer:     %s\nVersion:    %s\nReported:   %s ago\n\n"+
			"Policy\n  Synced:   %s\n  Rules:    %d\n  Mode:     %s",
		state,
		connFor,
		nonEmpty(st.Machine, "—"),
		nonEmpty(st.AgentID, "—"),
		nonEmpty(st.Server, "—"),
		nonEmpty(st.Version, "—"),
		shortDuration(time.Since(st.UpdatedAt)),
		synced,
		st.PolicyRules,
		nonEmpty(st.PolicyMode, "—"),
	)
	if st.LastError != "" {
		body += "\n\nLast error:\n" + st.LastError
	}
	showText("Agent status", body)
}
