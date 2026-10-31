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
	// name is the application, carried from the agent rather than parsed
	// back out of the title.
	//
	// The menu groups by it, and a title is a sentence built for display —
	// "Visual Studio Code — update" — so recovering the name from one meant
	// a list of suffixes to strip, kept in step by hand. The moment a new
	// wording was added without it, the same application appeared twice in
	// the menu under two names.
	name   string
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
	// stage is what the agent is doing about this row right now, as
	// opposed to what it decided. Empty for a settled row.
	stage string
	// blocked marks software a POLICY RULE forbids.
	//
	// Separate from "not requestable", although a blocked row is both. The
	// menu has to say which of the two it is: "cannot be verified" on an
	// application the organisation has deliberately forbidden sends somebody
	// looking for a signature problem that does not exist.
	blocked bool
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
	// updates reports that acting on this row REPLACES a version already
	// installed, rather than adding one.
	updates bool
	// versions is "1.2 → 1.3" where both are known.
	versions string
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
	blocked := pendinginstall.Outcome(p.Outcome).BlockedByPolicy()

	row := softwareRow{
		name:        label,
		title:       label,
		detail:      p.Reason,
		path:        p.Path,
		requestable: requestable,
		blocked:     blocked,
		stage:       p.Stage,
		closed:      p.Closed,
		requested:   p.Requested,
		canDrag:     p.CanDrag,
		installed:   p.Installed,
		removable:   p.Removable,
		updates:     p.Updates,
		versions:    versionChange(p.InstalledVersion, p.Version),
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

	// Something on screen for the whole of it.
	//
	// The copy runs for seconds on a small application and a minute on a
	// large one, and until now the dialog closed the moment somebody
	// clicked Install and nothing replaced it. From where they were sitting
	// the click did nothing, and the application appeared — or did not —
	// some time later with no way to tell which was happening.
	// Three words for the one operation, because a dialog that says
	// "Installed" about a version somebody has just REPLACED reads as a
	// second copy having appeared beside the one they were using.
	name := appNameOf(row)
	running, done, verb := "Installing", "Updated", "update"
	if !row.updates {
		done, verb = "Installed", "install"
	} else {
		running = "Updating"
	}
	progressShow(running+" "+name, "This will not ask you for a password.")
	defer progressHide()

	// Nothing else may open a window while this one is up.
	//
	// pumpRunLoop below keeps the run loop turning so the bar animates,
	// which also lets the refresh timer fire — and that timer can decide to
	// put up a dialog of its own. Without this, somebody installing from
	// the menu could be asked about a different disk image on top of their
	// own install. Restored rather than cleared, because the caller may
	// already hold it.
	wasAsking := askingNow
	askingNow = true
	defer func() { askingNow = wasAsking }()

	if err := agentstatus.RequestInstall(row.path); err != nil {
		showText("Could not install",
			fmt.Sprintf("The request could not be written:\n\n%v\n\n"+
				"This usually means the agent is not running.", err))
		return
	}

	if problem, ok := waitForInstall(); ok {
		// Hidden before the result dialog, not after: an alert on top of a
		// still-spinning progress bar reads as two things happening.
		progressHide()
		if problem == "" {
			showText(done, name+" is ready to use.")
		} else {
			showText("Could not "+verb+" "+name, problem)
		}
		return
	}
	progressHide()
	showText(running+" "+name,
		name+" is still being "+verb+"d, and will finish by itself.\n\n"+
			"You were not asked for a password because this Mac "+verb+"s "+
			"approved software for you.")
}

// waitForInstall gives the agent a few seconds to answer.
//
// Bounded, because a copy of a large application takes longer than anybody
// wants to watch a frozen menu, and because the agent might not be running
// at all — in which case no answer is ever coming and the dialog would never
// close.
func waitForInstall() (problem string, answered bool) {
	// Two different waits, because there are two different silences.
	//
	// Silence at the START means nobody picked the request up: the agent is
	// not running, or it refused the path. Nothing is ever coming, and a
	// progress panel sitting there for twenty minutes would be the longest
	// possible way to say so.
	//
	// Silence LATER, after progress has been seen, means a copy is running
	// and simply has not finished. Giving up on that would take the bar off
	// the screen a few percent into every large application — the moment
	// somebody most wants to look at it.
	//
	// So the budget starts short and is extended the first time the agent
	// actually says something.
	budget := startWaitTicks
	started := false

	for i := 0; i < budget; i++ {
		if app, problem := agentstatus.TakeInstallResult(); app != "" {
			return problem, true
		}

		// The bar is moved on every tick of this loop, which is the only
		// place in this process that is awake while an install runs.
		if drawInstallProgress() && !started {
			started = true
			budget = installWaitTicks
		}

		// Not time.Sleep. See pumpRunLoop: sleeping here freezes the
		// progress bar this wait exists to keep on screen.
		pumpRunLoop(installWaitTick)
	}
	return "", false
}

const (
	installWaitTick = 250 * time.Millisecond
	// startWaitTicks is how long to wait for the agent to say ANYTHING.
	//
	// Short, because the thing it is detecting is an agent that is not
	// running, and that answer does not improve by waiting for it.
	startWaitTicks = 10 * 4 // ten seconds
	// installWaitTicks bounds the wait at twenty minutes.
	//
	// It was six seconds, from when this loop only had to catch a result
	// that either arrived or did not. Now it is drawing the progress bar,
	// and giving up after six seconds would take the bar off the screen a
	// few percent into every large application — which is the moment
	// somebody most wants to look at it.
	//
	// Still bounded, because the agent may not be running at all, in which
	// case no answer is ever coming. Twenty minutes matches the timeout the
	// agent puts on running an installer package, so this outlives the work
	// rather than the other way round.
	installWaitTicks = 20 * 60 * 4
)

// drawInstallProgress moves the bar to wherever the agent says it has got.
//
// Silent when there is nothing to report: an install that has not begun, or
// has just finished, leaves the file empty, and the bar stays where it was
// rather than snapping to zero.
// It reports whether the agent said anything at all, which is what tells the
// caller that work has actually begun.
func drawInstallProgress() bool {
	p, ok := agentstatus.ReadInstallProgress()
	if !ok {
		return false
	}

	// Percent is -1 when the agent could not measure the work. Passed
	// straight through: the bar goes back to sweeping, which is the honest
	// picture, rather than sitting at a number nobody computed.
	progressUpdate(p.Percent, progressWords(p))
	return true
}

// progressWords is the line under the bar.
//
// The phase where the thing doing the work names one — an installer package
// says "Preparing the disk…" and that is better than any sentence written
// here. Sizes otherwise, because "148 MB of 412 MB" answers the question a
// percentage does not: how much longer.
func progressWords(p agentstatus.InstallProgress) string {
	if p.Phase != "" {
		return p.Phase
	}
	if p.Total > 0 {
		return fmt.Sprintf("%s of %s", humanBytes(p.Done), humanBytes(p.Total))
	}
	return "This will not ask you for a password."
}

// humanBytes is a size somebody can read at a glance.
//
// Decimal units, matching Finder. A bar that says 412 MB beside a Finder
// window saying 432 MB about the same file invites the question of which one
// is wrong, and the answer — that one of them counted in units of 1024 — is
// of no use to anybody waiting for a copy.
func humanBytes(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.0f MB", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.0f KB", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

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

// versionChange reads as a move from one version to another, where both are
// known. Empty when either is missing: "→ 1.3" alone says nothing somebody
// can act on.
func versionChange(installed, offered string) string {
	if installed == "" || offered == "" || installed == offered {
		return ""
	}
	return installed + " → " + offered
}

// appNameOf is the row title without the status that was appended to it.
func appNameOf(row softwareRow) string {
	if row.name != "" {
		return row.name
	}
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

// showCheckingPanel keeps a panel up while the agent is still working out
// what a freshly mounted image contains, and takes it down when it is done.
//
// This is the gap between double-clicking a disk image and being told
// anything. It is not short: the agent will not judge a half-mounted bundle,
// so it waits for the same answer twice, and a Mac that says nothing for
// those seconds has — from where the person is sitting — ignored the
// double-click entirely. They go looking in Finder and meet the password
// sheet, which is the one thing this feature exists to prevent.
//
// Driven from the refresh tick rather than by waiting: the panel goes up on
// the tick that sees a checking row and comes down on the tick that does
// not. If the answer settles inside one tick nothing is ever shown, which is
// right — there was nothing to wait for.
func showCheckingPanel(rows []softwareRow) {
	// Never on top of a dialog. A floating panel over a question somebody is
	// reading is a panel covering the thing they have to answer.
	if askingNow {
		return
	}
	for _, r := range rows {
		if r.stage != stageChecking {
			continue
		}
		name := appNameOf(r)
		if name == "" {
			name = "this disk image"
		}
		progressShow("Checking "+name,
			"Making sure it is allowed before installing it.")
		checkingPanelUp = true
		return
	}
	if checkingPanelUp {
		progressHide()
		checkingPanelUp = false
	}
}

// checkingPanelUp is whether THIS panel is the one on screen, so the install
// panel is never torn down by the checking tick that follows it.
var checkingPanelUp bool

// askAboutNewInstalls puts the question in front of somebody who has just
// opened a disk image, rather than waiting for them to find the menu.
func askAboutNewInstalls(rows []softwareRow) {
	if askingNow {
		return
	}
	// A question replaces the panel. Asking from underneath it would be a
	// dialog somebody cannot read.
	if checkingPanelUp {
		progressHide()
		checkingPanelUp = false
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

	// Forbidden by a rule: a statement, and no request.
	//
	// Checked before the requestable wording below, which would otherwise
	// promise that somebody has been asked. Nobody has, and nobody will be:
	// the agent stopped raising requests against a rule because the portal
	// refuses to approve them, so the request was only ever a dead letter
	// that left the person waiting for an answer that was never coming.
	//
	// What they are told instead is the thing they can act on — who to go
	// to, and that the rule itself has to change.
	if row.blocked {
		showText(name+" is not allowed on this Mac",
			row.detailWithoutClickHint()+"\n\n"+
				"No approval request has been raised, and asking again here "+
				"will not change it: this is a policy rule, and nobody can "+
				"approve an exception to one. If you need "+name+" for your "+
				"work, ask whoever manages this Mac to change the rule.")
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
