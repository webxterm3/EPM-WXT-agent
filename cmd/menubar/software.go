package main

import (
	"fmt"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
	"github.com/Yesveer/wxt-agent/internal/pendinginstall"
)

// The installers sitting in this person's downloads, as a menu.
//
// The agent decides; this shows. It has to be that way round — this program
// runs as the logged-in user and can read neither another account's
// downloads, nor the system trust store that says who signed a package, nor
// the policy at all.

// softwareRow is one line in the Software submenu.
type softwareRow struct {
	title  string
	detail string
	path   string
	// requestable rows are the clickable ones: the ones where an approver
	// could change the answer.
	requestable bool
	// closed reports that the agent has ejected the image this was in, so
	// the wording can say so rather than talk about dragging something that
	// is no longer on screen.
	closed bool
	// installable rows are the ones the agent will put into /Applications
	// when asked. Clicking one installs it; there is nothing to approve.
	installable bool
	// requested reports that the approval has already been asked for, so
	// the row and the dialog say so rather than offering to ask again.
	requested bool
	// canDrag reports that the window onto /Applications is open, so
	// dragging will actually work. When it is not, saying "drag it" is
	// telling somebody to do the one thing that ends in a password prompt.
	canDrag bool
	// installed marks an application already on the machine. Clicking one
	// removes it, or asks for permission to.
	installed bool
	// removable reports that policy allows this person to remove it.
	removable bool
}

// clickable reports whether a row does anything when clicked.
func (r softwareRow) clickable() bool {
	return r.requestable || r.installable || r.installed
}

// shown is the list the menu was last built from, so a click can be mapped
// back to a file. Guarded because Cocoa calls in on the main thread and the
// refresh timer is the same thread, but a future change need not be.
var (
	shownMu sync.Mutex
	shown   []softwareRow
)

// pendingForThisUser builds the rows and remembers them.
func pendingForThisUser() []softwareRow {
	st, ok := agentstatus.Read()
	if !ok {
		return nil
	}

	me := currentUsername()
	rows := make([]softwareRow, 0, len(st.PendingInstalls))
	for _, p := range st.PendingInstalls {
		// Only this person's downloads. Offering to install from somebody
		// else's folder is a surprising thing to put in front of somebody,
		// and on a shared Mac it would list files they cannot even see.
		if me != "" && p.User != "" && !strings.EqualFold(p.User, me) {
			continue
		}
		rows = append(rows, rowFor(p))
	}

	shownMu.Lock()
	shown = rows
	shownMu.Unlock()
	return rows
}

func rowFor(p agentstatus.PendingInstall) softwareRow {
	label := p.Label
	if label == "" {
		label = "Unnamed application"
	}

	// Asked of the agent's own predicate rather than decided again here.
	//
	// These were two lists once — this switch said which rows could be
	// clicked, and the agent said which requests it would send — and they
	// drifted. The menu offered an approval route for software no rule
	// mentions, which is the ordinary case in a default-deny estate; the
	// agent still tested for "blocked" and dropped the rest. Nothing failed:
	// the dialog said the request had been made, and it had not.
	requestable := pendinginstall.Outcome(p.Outcome).Requestable()

	row := softwareRow{
		title:       label,
		detail:      p.Reason,
		path:        p.Path,
		requestable: requestable,
		closed:      p.Closed,
		requested:   p.Requested,
		canDrag:     p.CanDrag,
		installed:   p.Installed,
		removable:   p.Removable,
	}

	if p.Installed {
		// Dragging an application to the Trash means deleting a directory
		// out of /Applications, which a standard user cannot do — so Finder
		// asks for an administrator password. The agent does the move
		// instead, and this row is how somebody asks it to.
		// Only removable applications are published, so there is one shape
		// here. Listing the rest turned the menu into an inventory of the
		// Mac in which everything already installed offered to raise an
		// approval request — software that is already there is not something
		// anybody has to decide about.
		row.installable = false
		row.requestable = false
		row.removable = true
		row.title = label + " — remove"
		row.detail = "This Mac will move " + label + " to your Trash. You " +
			"will not be asked for an administrator password."
		return row
	}

	switch {
	case p.Outcome == "installable":
		// Clicking installs it.
		//
		// This used to be an unclickable row, because the design was that
		// the person drags the application across themselves through a
		// window the agent had opened on /Applications. A managed Mac
		// refuses to let that window be opened at all — even to root — so
		// the drag met Finder's administrator password sheet instead, for
		// software that had just been approved. The agent runs as root and
		// does the copy itself.
		row.installable = true
		row.title = label + " — approved, click to install"
		if p.CanDrag {
			row.title = label + " — approved, drag it across"
		}
		if p.Publisher != "" {
			row.detail = "Signed by " + p.Publisher + ". " + row.detail
		}

	case requestable && p.Requested:
		// Already asked for, automatically, when the image was opened.
		row.title = label + " — approval requested"
		row.detail = p.Reason + " Somebody who administers this Mac has been " +
			"asked. Open the disk image again once they have decided."

	case requestable:
		row.title = label + " — needs approval"
		row.detail = p.Reason + " Click to ask for approval."

	default:
		// Unverified, and NOT offered an approval route: the problem is the
		// signature, and an administrator saying yes would not change it —
		// they would be approving whatever happened to be in the image.
		row.title = label + " — cannot be verified"
	}

	if p.Closed && p.Outcome != "installable" {
		row.detail += " The disk image has been closed."
	}
	return row
}

// requestApproval asks for the application whose row was clicked.
func requestApproval(index int) {
	shownMu.Lock()
	var row softwareRow
	if index >= 0 && index < len(shown) {
		row = shown[index]
	}
	shownMu.Unlock()

	if row.installed {
		removeNow(row)
		return
	}
	if row.installable {
		installNow(row)
		return
	}
	sendInstallRequest(row)
}

// removeNow asks the agent to take an application off the machine, or to ask
// on the person's behalf when policy does not allow it.
func removeNow(row softwareRow) {
	if row.path == "" {
		return
	}
	name := appNameOf(row)

	if !confirmText("Remove "+name+"?",
		"This Mac will move "+name+" to your Trash. You will not be asked for "+
			"an administrator password, and you can put it back from the "+
			"Trash if you change your mind.",
		"Remove", "Cancel") {
		return
	}

	if err := agentstatus.RequestInstall(row.path); err != nil {
		showText("Could not ask the agent",
			fmt.Sprintf("The request could not be written:\n\n%v\n\n"+
				"This usually means the agent is not running.", err))
		return
	}

	problem, answered := waitForInstall()
	switch {
	case answered && problem != "":
		showText("Could not remove "+name, problem)
	case answered:
		showText("Removed", name+" is in your Trash.")
	default:
		showText("Removing", name+" is being moved to your Trash.")
	}
}

// installNow asks the agent to install approved software, and says what
// happened.
//
// The agent does the work — it is the only thing on the machine that can
// write into /Applications — so this waits for its answer rather than
// announcing success it has not seen. Saying "installed" and being wrong is
// how somebody goes looking in Applications for something that is not there.
func installNow(row softwareRow) {
	if row.path == "" {
		return
	}
	if err := agentstatus.RequestInstall(row.path); err != nil {
		showText("Could not install",
			fmt.Sprintf("The request could not be written:\n\n%v\n\n"+
				"This usually means the agent is not running.", err))
		return
	}

	name := appNameOf(row)
	if problem, ok := waitForInstall(); ok {
		if problem == "" {
			showText("Installed", name+" is now in your Applications folder.")
		} else {
			showText("Could not install", name+" was not installed.\n\n"+problem)
		}
		return
	}
	showText("Installing",
		name+" is being installed. It will appear in your Applications "+
			"folder shortly.\n\nYou were not asked for a password because "+
			"this Mac installs approved software for you.")
}

// waitForInstall gives the agent a few seconds to answer.
//
// Bounded, because a copy of a large application takes longer than anybody
// wants to watch a frozen menu, and because the agent might not be running
// at all — in which case no answer is ever coming and the dialog would never
// close.
func waitForInstall() (problem string, answered bool) {
	for i := 0; i < installWaitTicks; i++ {
		if app, problem := agentstatus.TakeInstallResult(); app != "" {
			return problem, true
		}
		time.Sleep(installWaitTick)
	}
	return "", false
}

const (
	installWaitTick  = 250 * time.Millisecond
	installWaitTicks = 24 // six seconds
)

// sendInstallRequest raises the approval request and says what happened.
//
// Only requestable rows reach here. An approved one is installed instead,
// and an unverified one is not something an approval can fix — the signature
// is the problem, and an administrator saying yes would not change it.
func sendInstallRequest(row softwareRow) {
	if !row.requestable || row.path == "" {
		return
	}

	if err := agentstatus.RequestInstall(row.path); err != nil {
		showText("Could not ask for approval",
			fmt.Sprintf("The request could not be written:\n\n%v\n\n"+
				"This usually means the agent is not running.", err))
		return
	}

	showText("Approval requested",
		"Somebody who administers this machine has been asked to approve "+
			appNameOf(row)+".\n\n"+
			"You will not be told here when they decide. Open the disk image "+
			"again afterwards: if it was approved, it will install without "+
			"asking you for anything.")
}

// appNameOf is the row title without the status that was appended to it.
func appNameOf(row softwareRow) string {
	name := row.title
	for _, suffix := range []string{
		" — needs approval", " — approval requested",
		" — cannot be verified", " — approved, click to install",
		" — approved, drag it across", " — remove", " — ask to remove",
	} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

// askingNow stops a second dialog opening on top of the first.
//
// The refresh timer is scheduled in the default run loop mode and so does not
// fire while a modal dialog is up, which means this cannot trigger today. It
// is here because that is an Apple implementation detail: anybody adding the
// timer to the common run loop modes would otherwise turn a mounted volume
// into an unbounded stack of dialogs, and would find out from a user.
var askingNow bool

// askAboutNewInstalls puts the question in front of somebody who has just
// opened a disk image, rather than waiting for them to find the menu.
func askAboutNewInstalls(rows []softwareRow) {
	if askingNow {
		return
	}
	row, ok := installPromptState.next(rows)
	if !ok {
		return
	}
	// Belt and braces. next() does not offer installed software, and if it
	// ever did again the wording below would describe the wrong thing —
	// which is exactly how an installed, allowed application came to be
	// shown a dialog headed "needs approval".
	if row.installed {
		return
	}

	askingNow = true
	defer func() { askingNow = false }()

	name := appNameOf(row)
	if row.installable {
		// What the dialog offers depends on whether dragging will work.
		//
		// The drag needs an access-control entry on /Applications, and a
		// managed Mac refuses to write one even to root. Telling somebody to
		// drag when that entry could not be opened is telling them to do the
		// one thing that ends in the administrator password sheet — which is
		// the prompt this whole feature exists to remove.
		//
		// So: where the window is open, say so and get out of the way, since
		// the gesture they already know is the drag. Where it is not, offer
		// the thing that does work.
		if row.canDrag {
			confirmText(name+" is allowed",
				"Drag "+name+" to your Applications folder as usual. You will "+
					"not be asked for an administrator password.\n\n"+
					row.detailWithoutClickHint(),
				"OK", "Cancel")
			return
		}

		if !confirmText(name+" is allowed",
			"This Mac does not let software be dragged into Applications, so "+
				"it will install "+name+" for you instead. You will not be "+
				"asked for an administrator password.\n\n"+
				row.detailWithoutClickHint(),
			"Install", "Cancel") {
			return
		}
		installNow(row)
		return
	}

	what := "dragging " + name + " across will not work yet"
	if row.closed {
		what = "the disk image has been closed"
	}

	if row.requested {
		// The ask went out when the image was opened. Nothing to decide, so
		// nothing is asked — a two-button question whose answer changes
		// nothing is a worse interruption than a statement.
		//
		// "If they allow it", not "it will install". Software a policy rule
		// forbids cannot be approved at all — the portal refuses, and the
		// rule has to change first. Promising the install would be telling
		// somebody to wait for something that is not coming.
		showText(name+" needs approval",
			"This Mac does not let software be installed without approval, so "+
				what+".\n\n"+row.detailWithoutClickHint()+"\n\n"+
				"Somebody who administers this Mac has been asked. You will not "+
				"be told here when they decide — if they allow it, open the disk "+
				"image again and it will install without asking you for anything.")
		return
	}

	agreed := confirmText(name+" needs approval",
		"This Mac does not let software be installed without approval, so "+
			what+".\n\n"+
			row.detailWithoutClickHint()+"\n\n"+
			"Ask somebody who administers this Mac about it? You will never be "+
			"asked for an administrator password — if they allow it, you open "+
			"the disk image again and install it yourself.",
		"Request approval", "Not now")
	if !agreed {
		return
	}
	sendInstallRequest(row)
}

var installPromptState = newInstallPrompts()

// detailWithoutClickHint drops the instruction that only makes sense in a
// menu. In a dialog there is a button, and telling somebody to click a row
// they are not looking at reads as though the dialog is the wrong thing.
func (r softwareRow) detailWithoutClickHint() string {
	return strings.TrimSpace(strings.Replace(r.detail, "Click to ask for approval.", "", 1))
}

// currentUsername is who is at the screen, or empty if it cannot be told.
func currentUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	// The agent records the account name as it appears in the home directory
	// path, which is the short name here too.
	if i := strings.LastIndexAny(u.Username, `\/`); i >= 0 {
		return u.Username[i+1:]
	}
	return u.Username
}
