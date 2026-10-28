package main

import (
	"strings"
	"testing"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
)

// Once the ask has gone out, the row says so rather than offering to ask
// again.
//
// The request is raised automatically the moment the image is opened —
// opening an installer IS the decision, and waiting for somebody to find a
// button means they have already been refused once for no reason they can
// see. A row still reading "click to ask" after that invites a second ask
// for something already asked.
func TestARowSaysTheApprovalHasAlreadyBeenAskedFor(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:     "Visual Studio Code",
		Outcome:   "no-policy",
		Reason:    "No policy rule covers Visual Studio Code.",
		Path:      "/Volumes/VS Code/Visual Studio Code.app",
		Requested: true,
		Closed:    true,
	})

	if !strings.Contains(row.title, "approval requested") {
		t.Errorf("title %q does not say the approval was already asked for", row.title)
	}
	if strings.Contains(row.detail, "Click to ask") {
		t.Errorf("detail still invites a second ask: %q", row.detail)
	}
	if !row.requested {
		t.Error("the row did not carry that the ask had gone out, so the dialog " +
			"will offer to make a request that already exists")
	}
}

// Until it HAS gone out — the agent may be offline — the row still offers.
// Otherwise somebody whose first ask never left the machine has no way to
// try again.
func TestARowStillOffersWhenTheAskNeverLeftTheMachine(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:     "Visual Studio Code",
		Outcome:   "no-policy",
		Reason:    "No policy rule covers Visual Studio Code.",
		Path:      "/Volumes/VS Code/Visual Studio Code.app",
		Requested: false,
	})

	if !row.requestable || !row.clickable() {
		t.Fatal("a request that never left the machine cannot be retried")
	}
	if !strings.Contains(row.detail, "Click to ask") {
		t.Errorf("detail %q does not tell anybody they can ask", row.detail)
	}
}

// Approved software is offered for installing, by the agent.
func TestAnApprovedRowOffersToInstall(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:     "Claude",
		Outcome:   "installable",
		Reason:    "Claude was approved for this machine.",
		Publisher: "Developer ID Application: Anthropic",
		Path:      "/Volumes/Claude/Claude.app",
	})

	if !row.installable || !row.clickable() {
		t.Fatal("approved software cannot be installed from the menu, and the " +
			"drag it would otherwise need is refused by macOS")
	}
	if row.requestable {
		t.Error("approved software is also offering to ask for approval")
	}
	if !strings.Contains(row.title, "install") {
		t.Errorf("title %q does not say it can be installed", row.title)
	}
}

// A bundle whose signature does not check out is neither.
func TestAnUnverifiedRowOffersNothing(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:   "Odd",
		Outcome: "unverified",
		Reason:  "Odd is not signed.",
		Path:    "/Volumes/Odd/Odd.app",
	})

	if row.clickable() {
		t.Error("an unverified bundle was offered an action; approval cannot fix " +
			"a signature and installing it is what must not happen")
	}
}

// Telling somebody to drag when dragging cannot work is telling them to do
// the one thing that ends in the administrator password sheet.
//
// The drag needs an access-control entry on /Applications, and a managed Mac
// refuses to write one even to root. The dialog said "drag it across" either
// way, so on those machines an ALLOWED application still met the password
// prompt — the prompt this whole feature exists to remove.
func TestAnAllowedRowSaysInstallWhenDraggingCannotWork(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:   "Claude",
		Outcome: "installable",
		Reason:  "Claude was approved for this machine.",
		Path:    "/Volumes/Claude/Claude.app",
		CanDrag: false,
	})

	if !row.installable || !row.clickable() {
		t.Fatal("with no drag window there is no way to install at all")
	}
	if strings.Contains(row.title, "drag") {
		t.Errorf("title %q tells somebody to drag on a Mac where the drag "+
			"window could not be opened", row.title)
	}
	if row.canDrag {
		t.Error("the row claims dragging works")
	}
}

// And where the window IS open, the drag is the gesture they already know.
func TestAnAllowedRowSaysDragWhenDraggingWorks(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:   "Claude",
		Outcome: "installable",
		Reason:  "Claude was approved for this machine.",
		Path:    "/Volumes/Claude/Claude.app",
		CanDrag: true,
	})

	if !strings.Contains(row.title, "drag") {
		t.Errorf("title %q does not mention the drag, which is what works here", row.title)
	}
	if !row.canDrag {
		t.Error("the row did not carry that dragging works, so the dialog will " +
			"offer to install instead of getting out of the way")
	}
}

// Dragging an application to the Trash means deleting a directory out of
// /Applications, which a standard user cannot do — so Finder asks for an
// administrator password. The agent does the move instead, and the row is
// how somebody asks it to.
func TestAnInstalledApplicationPolicyAllowsCanBeRemovedFromTheMenu(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:     "Slack",
		Outcome:   "installed",
		Installed: true,
		Removable: true,
		Path:      "/Applications/Slack.app",
	})

	if !row.clickable() || !row.installed || !row.removable {
		t.Fatal("an application policy allows cannot be removed from the menu, " +
			"so the only way left is the Trash drag that asks for a password")
	}
	if row.installable || row.requestable {
		t.Error("an installed application is offering to be installed or approved")
	}
	if !strings.Contains(row.title, "remove") {
		t.Errorf("title %q does not offer to remove it", row.title)
	}
}

// Software already installed is not something anybody has to decide about.
//
// The first version of this listed every application on the Mac, and every
// one policy did not allow offered to raise an approval request — including
// this agent. That turned the menu into an inventory and asked people to
// decide about software that was already there. Policy decides whether it
// may stay; the enforcement pass acts on that. The menu's job is the one
// thing a person cannot do for themselves: remove something without a
// password.
func TestApplicationsPolicyDoesNotAllowRemovingAreNotListed(t *testing.T) {
	row := rowFor(agentstatus.PendingInstall{
		Label:     "Docker Desktop",
		Outcome:   "installed",
		Installed: true,
		Removable: false,
		Path:      "/Applications/Docker Desktop.app",
	})

	// The agent does not publish these at all, so whatever the menu does
	// with one must not be to ask about it.
	if row.requestable {
		t.Error("an application that is already installed is offering to " +
			"raise an approval request")
	}
	if strings.Contains(row.title, "ask") {
		t.Errorf("title %q asks somebody to decide about software that is "+
			"already on the machine", row.title)
	}
}

// Somebody who meets Finder's password prompt has no way of knowing there
// is another way.
//
// That prompt comes from Finder, not from this product, and says nothing
// about the agent. The one place they are already looking when they give up
// is this menu, so it is the only place the working route can be said.
func TestTheMenuSaysWhereTheWorkingRouteIsWhenDraggingFails(t *testing.T) {
	note := withDragNote("macbook · http://192.168.1.8:8082",
		agentstatus.Status{DragUnavailable: true})

	if !strings.Contains(note, "Software") {
		t.Errorf("the menu does not point at the route that works: %q", note)
	}
	if !strings.Contains(note, "macbook") {
		t.Errorf("the note replaced the detail instead of adding to it: %q", note)
	}
}

// And says nothing when dragging works, because then there is nothing to say.
func TestTheMenuIsQuietWhenDraggingWorks(t *testing.T) {
	detail := "macbook · http://192.168.1.8:8082"
	if got := withDragNote(detail, agentstatus.Status{}); got != detail {
		t.Errorf("said something about dragging on a Mac where it works: %q", got)
	}
}
