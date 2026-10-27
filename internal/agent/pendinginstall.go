package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
	"github.com/Yesveer/wxt-agent/internal/pendinginstall"
)

// Installing software a user downloaded, for a user who may not install it.
//
// A standard user has no right to install anything, so an installer they
// downloaded sits on their disk and the error the operating system gives them
// explains nothing. The agent does have that right. Where policy allows the
// software it installs it for them; where policy forbids it, it says so in
// words.
//
// The agent decides and the menu bar shows. It has to be that way round: the
// menu bar runs as the logged-in user and can read neither another account's
// downloads, nor the system trust store that says who signed a package, nor
// the policy at all.

const (
	// scanInterval is how often the mounted volumes are looked at.
	//
	// Short, because this is what somebody is waiting on. They double-click
	// a disk image and the next thing they do is drag the application
	// across; everything downstream — the menu row, and the dialog offering
	// to ask for approval — cannot happen until this notices the mount.
	// Fifteen seconds meant the question arrived well after they had already
	// met the password prompt and concluded the Mac was broken.
	//
	// Affordable because a mounted image is verified once rather than on
	// every pass: codesign --deep --strict reads the whole bundle, and
	// repeating that on a timer would burn a core for as long as the image
	// stayed mounted. See the signer cache in internal/pendinginstall.
	scanInterval = 3 * time.Second

	// mountPoll is how often the agent looks for a volume APPEARING.
	//
	// Separate from, and far shorter than, scanInterval because the two ask
	// different questions at different prices. This one is a single
	// directory listing — measured at about 150 microseconds, so polling it
	// three times a second costs nothing — and it only triggers the
	// expensive pass when the set of mounted volumes has actually changed.
	//
	// It has to be this short. Somebody double-clicks a disk image and drags
	// almost at once; anything the agent has not decided by then meets the
	// administrator password sheet, which is the one thing this feature
	// exists to remove. Three seconds was long enough to lose that race in
	// ordinary use.
	mountPoll = 300 * time.Millisecond

	// requestPoll is how often a pressed button is noticed. A stat of one
	// local file.
	requestPoll = time.Second
)

// pendingInstallState is what the loop knows, shared with the request handler.
type pendingInstallState struct {
	mu sync.Mutex
	// mounted is keyed by mount point, which is what tells one open image
	// from another and what disappears when one is ejected.
	mounted map[string]pendinginstall.MountedDecision

	// refused are decisions whose image the agent has since closed.
	//
	// Kept because closing the image is what makes the refusal painless —
	// no password sheet, no copy that is undone afterwards — and it would
	// be a poor trade if it also took away the way to ask. The menu row and
	// the dialog are both built from this, and so is the request itself, so
	// somebody can still ask for software after the window it was in has
	// gone.
	refused map[string]refusedInstall

	// ejecting is what a detach is already running for, so a volume that
	// takes a few seconds to close is not asked to close again on every
	// three-second scan.
	ejecting map[string]bool

	// confirmed is which volumes have given the same answer twice, and so
	// may be shown and acted on.
	confirmed map[string]bool

	// settling is the first, unconfirmed answer about a volume.
	//
	// Mounting a disk image is not atomic. The first look can land while the
	// volume is still appearing, and then PlistBuddy returns nothing for the
	// bundle identifier or codesign cannot read the signature — so a rule
	// that matches on those does not match, the application resolves to "no
	// rule covers this", and an approval request goes out for software an
	// operator had explicitly allowed. The request cannot be unsent and the
	// dialog cannot be unshown.
	//
	// So nothing is acted on until the same answer comes back twice. It
	// costs a few hundred milliseconds and covers every transient, not only
	// the two that have been seen.
	settling map[string]pendinginstall.Outcome

	// unsettled reports that some volume is waiting for its answer to be
	// confirmed, so the loop looks again soon rather than at the next
	// three-second tick.
	unsettled bool
}

// refusedInstall is one closed image, when it was closed, and whether the
// approval request for it has actually left the machine.
type refusedInstall struct {
	decision  pendinginstall.MountedDecision
	at        time.Time
	requested bool
}

// refusedMemory is how long a closed image stays askable.
//
// Long enough to cover somebody reading the dialog, going to find out who
// approves things, and coming back; short enough that a menu opened an hour
// later is not a list of everything ever refused.
const refusedMemory = 15 * time.Minute

// pendingInstallLoop watches people's downloads and acts on what it finds.
func (a *Agent) pendingInstallLoop(ctx context.Context) {
	if err := agentstatus.PrepareInstallRequest(); err != nil {
		a.logger.Warn("Could not prepare the install-request file — the menu bar's "+
			"Install buttons will not work on this machine", zap.Error(err))
	}
	if err := agentstatus.PrepareInstallResult(); err != nil {
		a.logger.Warn("The menu bar will not be told how installs went", zap.Error(err))
	}

	state := &pendingInstallState{
		mounted:   map[string]pendinginstall.MountedDecision{},
		refused:   map[string]refusedInstall{},
		ejecting:  map[string]bool{},
		settling:  map[string]pendinginstall.Outcome{},
		confirmed: map[string]bool{},
	}

	scan := time.NewTicker(scanInterval)
	defer scan.Stop()
	mounts := time.NewTicker(mountPoll)
	defer mounts.Stop()
	seen := pendinginstall.VolumeNames()
	poll := time.NewTicker(requestPoll)
	defer poll.Stop()

	// Anything a previous run left open is closed before this one starts.
	//
	// Every other revocation works from what this process granted, which is
	// exactly what a process that was killed does not have. The entry is on
	// the directory and survives a reboot, so without this one crash leaves
	// a standing write permission on /Applications for good.
	if left := pendinginstall.RevokeStaleDragGrants(); len(left) > 0 {
		a.logger.Warn("Closed drag-install windows left open by an earlier run",
			zap.Strings("users", left))
	}
	if left := pendinginstall.RevokeStaleBundleGrants(); len(left) > 0 {
		a.logger.Warn("Withdrew permission to remove applications, left by an earlier run",
			zap.Strings("grants", left))
	}

	a.rescanVolumes(state)

	for {
		select {
		case <-ctx.Done():
			// A window left open is a standing permission that nothing is
			// watching, and a stopped agent is exactly when nothing is.
			pendinginstall.RevokeAllDragGrants()
			pendinginstall.RevokeAllBundleGrants()
			return
		case <-mounts.C:
			// Only when something actually appeared or went away — or when
			// an answer is still waiting to be confirmed. The full pass
			// reads each bundle and verifies its signature; running it three
			// times a second regardless would be the agent making the
			// machine slower in order to be quick.
			//
			// The second condition is what makes confirmation fast: a volume
			// whose first answer has not been seen twice is looked at again
			// in a few hundred milliseconds rather than at the next
			// three-second tick, so waiting for certainty costs almost
			// nothing.
			state.mu.Lock()
			waiting := state.unsettled
			state.mu.Unlock()

			if now := pendinginstall.VolumeNames(); !sameVolumes(seen, now) {
				seen = now
				a.rescanVolumes(state)
			} else if waiting {
				a.rescanVolumes(state)
			}
		case <-scan.C:
			// Anything that could not be reported earlier goes out here, so
			// a report lost to a momentary disconnect is not lost for good.
			a.retryUnreportedInstalls()

			// On a timer as well, because policy changes under a volume that
			// is already mounted: an approval arriving is a different answer
			// about the same disk image.
			seen = pendinginstall.VolumeNames()
			a.rescanVolumes(state)
		case <-poll.C:
			if bundle := agentstatus.TakeInstallRequest(); bundle != "" {
				// One channel, two meanings, told apart by where the path
				// is. A bundle in /Applications is already installed, so
				// the only thing anybody can be asking for is its removal;
				// one under /Volumes is sitting in a mounted image.
				if pendinginstall.IsInstalledPath(bundle) {
					go a.removeInstalled(bundle)
				} else {
					go a.requestApproval(volumeOf(bundle), state)
				}
			}
		}
	}
}

// rescanVolumes looks at what is mounted now and acts on it.
//
// Mounts, not a folder listing. The first version read everybody's Downloads
// and it was wrong twice over: a long-lived download folder is full of images
// nobody cares about any more, so the list was noise; and a file sitting
// there is not a decision anybody made. Double-clicking is the decision, and
// it is what puts the image under /Volumes.
func (a *Agent) rescanVolumes(state *pendingInstallState) {
	// Nil when no policy has reached this machine yet, which Decide reports
	// as its own answer rather than guessing.
	var eff *apppolicy.Effective
	if a.policies != nil {
		eff = a.policies.Current()
	}

	mounted := pendinginstall.MountedApps()

	state.mu.Lock()
	defer state.mu.Unlock()

	next := make(map[string]pendinginstall.MountedDecision, len(mounted))
	for _, app := range mounted {
		d := pendinginstall.DecideMounted(app, eff)
		next[app.Volume] = d

		// Logged when the answer CHANGES, not on every scan.
		//
		// Everything downstream — the dialog, the row, the eject, the
		// request — follows from this one line, and without it the only way
		// to find out why an application was refused is to guess. Which
		// rule, and on what identity, is exactly what somebody needs when
		// they believe they allowed something and the Mac disagrees.
		if was, seen := state.mounted[app.Volume]; !seen || was.Outcome != d.Outcome {
			a.logger.Info("Decided about mounted software",
				zap.String("application", app.Name),
				zap.String("outcome", string(d.Outcome)),
				zap.String("publisher", app.Publisher),
				zap.String("bundle_id", app.BundleID),
				zap.String("judged_path", pendinginstall.InstalledPathFor(app.Name)),
				zap.String("rule", d.Rule),
				zap.String("policy", d.Policy),
				// Told apart from "nobody ever approved this", which it
				// otherwise looks identical to.
				zap.Bool("approval_already_used", eff.HasSpentApproval(app.Name, time.Now())),
				zap.Bool("enforcing", eff.Enforcing()))
		}
	}
	state.mounted = next

	// Who is at the screen. The window is opened for THEM: a disk image is
	// mounted system-wide, but the person dragging out of it is whoever is
	// logged in, and granting write to anybody else would be granting it to
	// somebody who is not there.
	user := pendinginstall.ConsoleUser()

	// Close anything that cannot be installed, and remember it.
	//
	// INCLUDING when no policy has arrived yet. That carve-out was wrong:
	// it was meant to avoid interfering with a machine nobody had told
	// anything, but the thing it actually produced was the administrator
	// password sheet — because withholding the window IS that sheet. A
	// freshly enrolled Mac, which is exactly the common case, got the one
	// prompt this whole feature exists to remove.
	//
	// Under default deny, "no policy has reached this machine" and "no rule
	// covers this software" are the same answer, and the answer is not yet.
	// The approval route still works: the request goes out as soon as the
	// agent has a connection, which is also what brings the policy.
	// Audit mode watches; it does not act.
	//
	// Ejecting somebody's disk image is acting, and so is handing out
	// permission to remove an application. Neither looked at the mode at
	// all, so a policy saved in audit — the mode somebody chooses precisely
	// to find out what it WOULD do — took effect on every Mac in scope.
	enforcing := eff.Enforcing()

	var toEject, toRequest []string
	unsettled := false
	now := time.Now()
	for volume, d := range next {
		// Confirmed BEFORE anything else — shown, acted on or forgotten.
		//
		// Mounting a disk image is not atomic. The first look can land while
		// the volume is still appearing, and then PlistBuddy returns nothing
		// for the bundle identifier or codesign cannot read the signature —
		// so a rule that matches on those does not match, and software an
		// operator explicitly allowed comes back as "no rule covers this".
		// Nothing is acted on, and nothing is SHOWN, until the same answer
		// comes back twice: the menu bar builds its dialog from what is
		// published, so publishing an unconfirmed answer puts the wrong
		// question in front of somebody just as surely.
		//
		// This is first in the loop, not after the installable case, because
		// every answer has to be confirmed — including the one that says the
		// software is allowed.
		if was, seen := state.settling[volume]; !seen || was != d.Outcome {
			state.settling[volume] = d.Outcome
			unsettled = true
			continue
		}
		state.confirmed[volume] = true

		if d.Outcome == pendinginstall.OutcomeInstallable {
			// The answer has changed — usually because an approval arrived.
			// Forgotten at once, so the row stops saying the image was
			// closed and so a LATER refusal of the same volume asks again
			// rather than being suppressed by a stale fifteen-minute record.
			delete(state.refused, volume)
			delete(state.ejecting, volume)
			continue
		}
		if !enforcing {
			// Reported in the menu, so somebody can see what the policy
			// would do, but nothing is closed and nothing is asked for.
			continue
		}

		if _, seen := state.refused[volume]; !seen && d.Outcome.Requestable() {
			// Ask AS SOON AS the image is opened, without waiting for
			// anybody to find a button.
			//
			// Opening an installer is the decision; by the time somebody has
			// read a dialog and clicked, they have already been refused once
			// for no reason they can see. Raising it here also means the ask
			// goes out every time they try, which is what somebody expects
			// after their first attempt went nowhere.
			//
			// Requestable(), so an unverified bundle raises nothing. The
			// signature is what is missing, and no approval can supply it —
			// asking anyway puts a request in front of somebody that cannot
			// be redeemed whatever they decide.
			//
			// It cannot flood an approver: the backend keeps one pending
			// request per machine per application and drops repeats.
			toRequest = append(toRequest, volume)
		}
		state.refused[volume] = refusedInstall{
			decision:  d,
			at:        now,
			requested: state.refused[volume].requested,
		}
		if !state.ejecting[volume] {
			state.ejecting[volume] = true
			toEject = append(toEject, volume)
		}
	}
	for volume := range state.settling {
		if _, stillMounted := next[volume]; !stillMounted {
			delete(state.settling, volume)
			delete(state.confirmed, volume)
		}
	}
	state.unsettled = unsettled

	reviseRefused(state.refused, state.ejecting, next, eff, now)

	// Every mounted application has to be installable, not merely one of
	// them.
	//
	// The window is one entry on /Applications as a whole; it cannot be
	// opened for a single application. Granting it because SOMETHING
	// approved is mounted would let a second, refused image be dragged in
	// beside it — and that second image is the whole reason any of this
	// exists. Refused images are closed above, so in practice this withholds
	// the window only for the seconds between a decision and the detach, or
	// for as long as an image is too busy to close.
	approved := len(next) > 0
	for _, d := range next {
		if d.Outcome != pendinginstall.OutcomeInstallable {
			approved = false
			break
		}
	}

	switch {
	case approved && user != "":
		// Best effort, and nothing depends on it.
		//
		// Where macOS allows the entry, dragging the application across
		// works as it does on any Mac. Where it does not — and a managed Mac
		// refuses it even to root — the agent does the copy itself when the
		// person asks, so the outcome is the same and no password is ever
		// requested either way.
		//
		// Reported once per run rather than on every scan. It used to warn
		// every three seconds for as long as an approved image was mounted,
		// which buried everything else in the log.
		err := pendinginstall.GrantDragInstall(user)
		a.dragWindowOpen.Store(err == nil)
		if err != nil && !a.dragWindowRefused {
			a.dragWindowRefused = true
			a.logger.Info("This Mac will not let the drag window be opened; "+
				"approved software will be installed by the agent instead",
				zap.String("user", user), zap.Error(err))
		}
	default:
		a.dragWindowOpen.Store(false)
		// Nothing approved is mounted. Closed immediately rather than left
		// to expire: the image being ejected is the clearest possible signal
		// that the window is no longer wanted.
		for _, u := range a.dragGrantedUsers() {
			pendinginstall.RevokeDragInstall(u)
		}
		a.setDragGranted(nil)
	}
	if approved && user != "" {
		a.setDragGranted(map[string]bool{user: true})
	}

	pendinginstall.ExpireDragGrants()
	a.refreshRemovalGrants(eff, user, next)
	a.publishMounted(state)

	// Both off the scan loop: hdiutil can take seconds, the gRPC send can
	// block, and the loop is also what notices a pressed button.
	for _, volume := range toRequest {
		go a.askAboutRefusedImage(state, volume)
	}
	for _, volume := range toEject {
		go a.closeRefusedImage(state, volume)
	}
}

// reviseRefused drops records that have aged out, and records whose answer
// has changed.
//
// A refused image has been EJECTED, so it is gone from the scan and its
// decision would otherwise be frozen at the moment it was refused. When the
// approval then arrived, the menu went on saying "needs approval" about
// software that had just been approved — which is precisely what somebody
// reports as the approval not working. There is nothing to install until
// they open the image again, which the dialog tells them; what must not
// happen is the machine still claiming it is refused.
func reviseRefused(
	refused map[string]refusedInstall,
	ejecting map[string]bool,
	mounted map[string]pendinginstall.MountedDecision,
	eff *apppolicy.Effective,
	now time.Time,
) {
	for volume, r := range refused {
		forget := now.Sub(r.at) > refusedMemory
		if !forget {
			if _, stillMounted := mounted[volume]; !stillMounted {
				again := pendinginstall.DecideMounted(r.decision.App, eff)
				forget = again.Outcome == pendinginstall.OutcomeInstallable
			}
		}
		if forget {
			delete(refused, volume)
			delete(ejecting, volume)
		}
	}
}

// maxInstalledRows caps the menu.
//
// A Mac has on the order of a hundred applications and a menu is not a file
// browser. Capped rather than paged, because somebody scrolling past fifty
// entries to find one is not being helped either.
const maxInstalledRows = 50

// installedRows is what the person may remove, and what they would have to
// ask about.
//
// Published because dragging an application to the Trash means deleting a
// directory out of /Applications, which a standard user cannot do — so
// Finder asks for an administrator password, which is the prompt this exists
// to remove. The agent does the move instead, and this is how somebody asks
// it to.
func (a *Agent) installedRows() []agentstatus.PendingInstall {
	removable := a.removableBundles()
	installed := pendinginstall.InstalledApps()
	if len(installed) > maxInstalledRows {
		installed = installed[:maxInstalledRows]
	}

	out := make([]agentstatus.PendingInstall, 0, len(installed))
	for _, bundle := range installed {
		// Only what this person may actually remove.
		//
		// Listing everything turned the menu into an inventory of the Mac in
		// which every application somebody already had offered to raise an
		// approval request — including this agent. Software that is already
		// installed is not something anybody has to decide about: policy
		// decides whether it may stay, and the enforcement pass acts on
		// that. The menu's job here is only the one thing a person cannot do
		// for themselves, which is remove something without a password.
		if !removable[bundle] || pendinginstall.IsOwnInstallPath(bundle) {
			continue
		}
		id := pendinginstall.InstalledIdentity(bundle)
		out = append(out, agentstatus.PendingInstall{
			Path:      bundle,
			Label:     id.Name,
			Format:    "app",
			Publisher: id.Publisher,
			Outcome:   "installed",
			Installed: true,
			Removable: true,
		})
	}
	return out
}

// askAboutRefusedImage raises the approval request for an image the agent
// has just refused, and records whether it got out.
func (a *Agent) askAboutRefusedImage(state *pendingInstallState, volume string) {
	state.mu.Lock()
	r, known := state.refused[volume]
	state.mu.Unlock()
	if !known {
		return
	}

	sent := a.raiseApprovalRequest(r.decision)

	state.mu.Lock()
	if current, still := state.refused[volume]; still {
		current.requested = sent
		state.refused[volume] = current
	}
	// Republished so the menu bar stops offering to do what has been done.
	a.publishMounted(state)
	state.mu.Unlock()
}

// refreshRemovalGrants decides which installed applications this person may
// replace or remove without being asked for a password.
//
// Granted on each BUNDLE rather than on /Applications. Measured: `delete` on
// the bundle is enough to remove it even when the parent denies
// delete_child, so uninstalling and upgrading work without opening the whole
// directory to deletion — which would mean being allowed to remove Slack was
// being allowed to remove the security tooling beside it.
//
// Re-asserted every scan and withdrawn the moment policy stops saying yes,
// so a rule change applies at the next scan rather than whenever a ten
// minute window happens to run out.
func (a *Agent) refreshRemovalGrants(eff *apppolicy.Effective, user string, mounted map[string]pendinginstall.MountedDecision) {
	if user == "" || !eff.Enforcing() {
		// Nobody at the screen, nothing decided for this machine, or a
		// policy in audit mode. In every case there is nobody to grant to or
		// no basis to grant on — and a grant is an act, which audit does not
		// make.
		pendinginstall.RevokeAllBundleGrants()
		return
	}

	allow := map[string]bool{}

	// Upgrades. An installable image whose application is already installed
	// can only go in if Finder may delete what is there — that is what
	// replacing means. Covers the approved case too, which no rule allows.
	for _, d := range mounted {
		if d.Outcome != pendinginstall.OutcomeInstallable {
			continue
		}
		if existing := pendinginstall.InstalledBundleFor(d.App.Name); existing != "" {
			allow[existing] = true
		}
	}

	// Uninstalls. Anything a rule allows outright may also be removed:
	// software somebody is permitted to install is software they are
	// permitted to change their mind about.
	//
	// Judged on all four things policy can be written against, not two.
	//
	// This used to pass only the folder name and the path, leaving Publisher
	// and BundleID empty — and the matcher fails any rule that constrains a
	// field it is not given. So a rule allowing everything signed by
	// Microsoft granted nobody permission to remove anything: the publisher
	// it compared against was always "". Only rules written on the folder
	// name did anything, which is not what the person writing the policy was
	// told they were doing.
	//
	// Read through a cache, so a hundred applications do not mean a hundred
	// Info.plist reads and signature checks every three seconds.
	now := time.Now()
	installed := pendinginstall.InstalledApps()
	pendinginstall.ForgetUninstalledIdentities(installed)
	for _, bundle := range installed {
		id := pendinginstall.InstalledIdentity(bundle)
		name := id.Name
		verdict := eff.Evaluate(apppolicy.Program{
			Name: id.Name, Publisher: id.Publisher,
			BundleID: id.BundleID, Path: bundle,
		})
		if verdict.FromRule && verdict.Action == apppolicy.ActionAllow {
			allow[bundle] = true
			continue
		}
		// An approval covers removing it too. Somebody who was given
		// permission to put an application on this machine has permission to
		// take it off again; making them raise a second request to undo the
		// first would be a worse answer than either.
		//
		// RemovalApproved, not InstallApproved: the latter refuses to match
		// without the bundle identifier and publisher the approval was
		// granted against, so calling it with what is known here would look
		// like a lookup and never match. See its comment.
		if eff.RemovalApproved(name, now) {
			allow[bundle] = true
		}
	}

	for bundle := range allow {
		// Our own files never get one, and that refusal is not news.
		//
		// It used to go through the same reporting as a real one, so the
		// log said "This Mac will not let applications be made removable"
		// about the agent refusing itself — and because the message is
		// printed once per run, a genuine refusal afterwards was never
		// reported at all. The one line that would have answered whether
		// macOS allows a per-application entry was spent on the one case
		// that was never going to get one.
		if pendinginstall.IsOwnInstallPath(bundle) {
			continue
		}
		if err := pendinginstall.GrantBundleRemoval(user, bundle); err != nil && !a.removalGrantRefused {
			// Once per run, like the drag window, and at a level somebody
			// will actually see. If this Mac refuses per-application entries
			// too, then dragging an application to the Trash still asks for
			// a password and the agent has to do the removal as well.
			a.removalGrantRefused = true
			a.logger.Info("This Mac will not let applications be made removable",
				zap.String("bundle", bundle), zap.Error(err))
		}
	}
	pendinginstall.RevokeBundleGrantsExcept(user, allow)
	pendinginstall.ExpireBundleGrants()
	a.setRemovable(allow)
}

// removableBundles is what policy currently allows this person to remove.
func (a *Agent) removableBundles() map[string]bool {
	if m := a.removable.Load(); m != nil {
		return *m
	}
	return map[string]bool{}
}

func (a *Agent) setRemovable(m map[string]bool) {
	copied := make(map[string]bool, len(m))
	for k, v := range m {
		copied[k] = v
	}
	a.removable.Store(&copied)
}

// closeRefusedImage ejects one image the policy will not allow.
func (a *Agent) closeRefusedImage(state *pendingInstallState, volume string) {
	if err := pendinginstall.Eject(volume); err != nil {
		// Not an error worth raising to anybody: a busy volume is one
		// somebody is reading at this moment, and the next scan tries again.
		a.logger.Debug("Could not close a refused image yet", zap.Error(err))
		state.mu.Lock()
		delete(state.ejecting, volume)
		state.mu.Unlock()
		return
	}
	a.logger.Info("Closed an image whose software is not approved",
		zap.String("volume", volume))
	state.mu.Lock()
	delete(state.ejecting, volume)
	state.mu.Unlock()
}

// publishMounted writes what is mounted and what policy says, for the menu
// bar. Caller holds state.mu.
func (a *Agent) publishMounted(state *pendingInstallState) {
	row := func(d pendinginstall.MountedDecision, closed, requested bool) agentstatus.PendingInstall {
		return agentstatus.PendingInstall{
			Path:      d.App.BundlePath,
			Label:     d.App.Name,
			Format:    "app",
			Publisher: d.App.Publisher,
			Outcome:   string(d.Outcome),
			Reason:    d.Reason,
			Rule:      d.Rule,
			Policy:    d.Policy,
			Closed:    closed,
			Requested: requested,
			CanDrag:   a.dragWindowOpen.Load(),
		}
	}

	out := make([]agentstatus.PendingInstall, 0, len(state.mounted)+len(state.refused))
	for volume, d := range state.mounted {
		// Not shown until the answer has been confirmed.
		//
		// Gating only the eject and the request was not enough: the menu
		// bar builds its dialog from what is published, so an unconfirmed
		// answer still put "needs approval" in front of somebody for
		// software an operator had allowed. Mounting is not atomic, the
		// first look can read an empty bundle identifier, and a rule that
		// matches on one then does not match.
		if !state.confirmed[volume] {
			continue
		}
		// Our own installer is not offered. It is allowed, so that upgrading
		// the agent never needs a password, but the agent is already running
		// and updates itself — a row and a dialog asking whether to install
		// it are an offer to do something nobody has to decide, and they
		// came back every few seconds for as long as the image stayed open.
		if d.Own {
			continue
		}
		// Whether an ask has already gone out for THIS application, carried
		// across the image being closed and opened again.
		//
		// A mounted row used to report "not yet asked" unconditionally, so
		// somebody who had already raised a request, had the image ejected,
		// and opened it again was asked the same question from the start —
		// every time, for software already sitting in an approver's queue.
		out = append(out, row(d, false, state.refused[volume].requested))
	}
	// Images the agent has closed are published too, so the person can
	// still ask about software whose window it took away. One that is
	// somehow still mounted is published once, as the live one.
	for volume, r := range state.refused {
		if _, stillMounted := state.mounted[volume]; stillMounted {
			continue
		}
		out = append(out, row(r.decision, true, r.requested))
	}
	out = append(out, a.installedRows()...)
	a.pendingInstalls.Store(&out)
	a.publishStatus(a.connected.Load(), "")
}

// dragGrantedUsers is who currently has a window open, copied out so the
// caller can compare without holding the lock that guards it.
func (a *Agent) dragGrantedUsers() []string {
	if g := a.dragGranted.Load(); g != nil {
		return *g
	}
	return nil
}

func (a *Agent) setDragGranted(users map[string]bool) {
	out := make([]string, 0, len(users))
	for u := range users {
		out = append(out, u)
	}
	a.dragGranted.Store(&out)
}

// InstallRequestDiscriminator carries an endpoint's request for software it
// is not allowed to install.
//
// Agent-to-server, which is the safe direction: the backend ignores
// discriminators it does not know, so an older backend simply does nothing
// with this. The reverse — a new server-to-agent command id — would be
// shell-executed by any agent that predates it.
const InstallRequestDiscriminator = "__install_request__"

// InstallResultDiscriminator is the endpoint saying what became of an
// approval.
//
// Without it an approved request stays "approved" until its 24-hour window
// runs out, whether the software was installed in the first minute or never
// installed at all. An approver looking at the queue cannot tell the two
// apart, and the exception stays live long after it has been used.
//
// Must match the constant in the backend — pinned by a drift test, because a
// rename on either side would not fail a build. Requests would simply stop
// being completed, and nothing would say why.
const InstallResultDiscriminator = "__install_result__"

// installResultPayload is what the endpoint reports after acting on an
// approval.
//
// The same identity the request carried, so the backend can find the request
// this answers without the agent having to remember an id it was never told.
type installResultPayload struct {
	Application string `json:"application"`
	BundleID    string `json:"bundle_id"`
	Publisher   string `json:"publisher"`
	OSUser      string `json:"os_user"`
	// Problem is empty when it worked. A failure is reported too: an
	// approval that was used and failed is a different thing from one
	// nobody acted on, and only one of them needs somebody to look.
	Problem string `json:"problem,omitempty"`
}

// installRequestPayload is what the endpoint reports when somebody asks for
// software it refused.
//
// A named type rather than a map, so the backend's decoder has something to
// be pinned against. With a map there is nothing to compare: a renamed key
// decodes to the zero value on the far side, the request is raised with no
// application name and dropped, and the person who clicked is told it worked.
type installRequestPayload struct {
	Application string `json:"application"`
	Publisher   string `json:"publisher"`
	BundleID    string `json:"bundle_id"`
	Version     string `json:"version"`
	OSUser      string `json:"os_user"`
	// OSUserEmail is the directory address of whoever is at the screen, when
	// it can be established, and empty when it cannot.
	//
	// It is what lets an approver tell who asked: the macOS account name and
	// the address the portal knows somebody by are different namespaces, and
	// on an Entra-synced estate a queue row reading "yesveer" matches no
	// search and can be sent no decision mail.
	OSUserEmail string `json:"os_user_email"`
	// InstallPath is where this application would live once installed, and
	// is the path the endpoint JUDGED the policy at.
	//
	// Sent so the portal can reach the same verdict. A rule that matches on
	// a path cannot be evaluated by anything that does not know the path:
	// the backend built its subject without one, every path rule failed to
	// match, and an administrator was never warned that the application
	// they were about to approve is one their own policy forbids.
	InstallPath string `json:"install_path,omitempty"`
	Rule        string `json:"rule"`
	Policy      string `json:"policy"`
}

// requestApproval asks the portal to raise an access request for software
// policy currently forbids.
//
// The agent sends what it SAW — the application's own name, publisher and
// bundle id, read out of the bundle it refused — rather than anything the
// person typed. An approver deciding this is deciding about a specific signed
// application, not about a name somebody chose.
// currentPolicy is the policy in force, or nil when none has arrived.
func (a *Agent) currentPolicy() *apppolicy.Effective {
	if a.policies == nil {
		return nil
	}
	return a.policies.Current()
}

// removeInstalled takes an application off the machine on somebody's behalf.
func (a *Agent) removeInstalled(bundle string) {
	user := pendinginstall.ConsoleUser()
	name := pendinginstall.InstalledIdentity(bundle).Name

	// Only what policy allows, checked here as well as in the menu.
	//
	// The request file is writable by any account on the machine by design,
	// so what the menu offers is not what may arrive. A path policy does not
	// allow is refused rather than acted on.
	if !a.removableBundles()[bundle] {
		a.logger.Warn("Refused a removal policy does not allow",
			zap.String("bundle", bundle))
		agentstatus.ReportInstallResult(name,
			"Your organisation does not allow "+name+" to be removed from this Mac.")
		return
	}

	if err := pendinginstall.RemoveBundle(bundle, user); err != nil {
		a.logger.Error("Could not remove an application",
			zap.String("bundle", bundle), zap.Error(err))
		agentstatus.ReportInstallResult(name, err.Error())
		return
	}
	a.logger.Info("Removed an application on request",
		zap.String("application", name), zap.String("user", user))
	agentstatus.ReportInstallResult(name, "")
}

func (a *Agent) requestApproval(volume string, state *pendingInstallState) {
	state.mu.Lock()
	d, known := state.mounted[volume]
	if !known {
		// The image has been closed, which is what the agent does to
		// anything it will not install. Closing it must not also take away
		// the way to ask about it — that would leave somebody with a
		// refusal and no route at all.
		var r refusedInstall
		if r, known = state.refused[volume]; known {
			d = r.decision
		}
	}
	state.mu.Unlock()

	// Looked up among what the agent itself decided, never taken as an
	// instruction. The request file is writable by any user on the machine
	// by design, so a path it does not recognise is ignored.
	if !known {
		a.logger.Info("Ignoring an install request for something not mounted",
			zap.String("volume", volume))
		return
	}

	// Decided AGAIN, now, against the policy as it stands.
	//
	// The row somebody clicked carries an answer from up to a scan ago, and
	// a policy can arrive between the two. Acting on the older answer is how
	// an application a rule has just started forbidding gets installed
	// anyway, and how one that has just been allowed is still refused — in
	// both cases by a button the person pressed believing it reflected the
	// rules.
	//
	// The decision is the whole of what happens next, so it is taken at the
	// moment of acting rather than carried.
	fresh := pendinginstall.DecideMounted(d.App, a.currentPolicy())
	if fresh.Outcome != d.Outcome {
		a.logger.Info("The policy changed while the image was open",
			zap.String("application", d.App.Name),
			zap.String("was", string(d.Outcome)),
			zap.String("now", string(fresh.Outcome)))
	}
	d = fresh

	// Approved software is INSTALLED, here, by the agent.
	//
	// Not handed to the person to drag. The drag needed an access-control
	// entry on /Applications, and a real managed Mac refuses to write one
	// even to root — so the window never opened and Finder asked for an
	// administrator password, including for software somebody had just
	// approved. The agent already runs as root and can do the copy itself,
	// which needs no privacy grant, no configuration profile, and leaves no
	// standing permission behind.
	if d.Outcome == pendinginstall.OutcomeInstallable {
		a.installApproved(d)
		return
	}

	// Requestable(), NOT "blocked". In a default-deny estate the ordinary
	// answer is no-policy — nobody has written a rule about this software —
	// and that is the case somebody most needs to ask about. Testing for
	// blocked alone dropped every one of those on the floor AFTER the menu
	// bar had already said the request was sent, so the person was told it
	// had worked and no trace of it existed anywhere.
	if !d.Outcome.Requestable() {
		a.logger.Info("Nothing to do for this image",
			zap.String("application", d.App.Name),
			zap.String("outcome", string(d.Outcome)))
		return
	}

	a.raiseApprovalRequest(d)
}

// raiseApprovalRequest asks the portal to approve one application, and
// reports whether the ask actually left the machine.
//
// The return value matters. The menu bar used to announce that a request had
// been made as soon as it had written a local file, which is not the same
// thing — and when the agent then dropped it, the person was told it had
// worked and nothing existed anywhere.
func (a *Agent) raiseApprovalRequest(d pendinginstall.MountedDecision) bool {
	client := a.grpcSafe()
	if client == nil {
		a.logger.Info("Cannot ask for approval yet — the agent is not connected",
			zap.String("application", d.App.Name))
		return false
	}

	payload, err := json.Marshal(installRequestPayload{
		Application: d.App.Name,
		Publisher:   d.App.Publisher,
		BundleID:    d.App.BundleID,
		Version:     d.App.Version,
		OSUser:      pendinginstall.ConsoleUser(),
		OSUserEmail: pendinginstall.ConsoleUserEmail(),
		InstallPath: pendinginstall.InstalledPathFor(d.App.Name),
		Rule:        d.Rule,
		Policy:      d.Policy,
	})
	if err != nil {
		a.logger.Warn("Could not describe the application to ask about",
			zap.String("application", d.App.Name), zap.Error(err))
		return false
	}

	if err := client.SendStatusUpdate(InstallRequestDiscriminator, string(payload)); err != nil {
		a.logger.Warn("Could not send the approval request", zap.Error(err))
		return false
	}
	a.logger.Info("Approval requested for software that is not allowed",
		zap.String("application", d.App.Name),
		zap.String("user", pendinginstall.ConsoleUser()))
	return true
}

// sameVolumes reports whether two sorted listings are equal.
func sameVolumes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// installApproved puts an approved application into /Applications.
func (a *Agent) installApproved(d pendinginstall.MountedDecision) {
	err := pendinginstall.InstallBundle(d.App.BundlePath)
	if err != nil {
		a.logger.Error("Could not install approved software",
			zap.String("application", d.App.Name), zap.Error(err))
		agentstatus.ReportInstallResult(d.App.Name, err.Error())
	} else {
		a.logger.Info("Installed approved software",
			zap.String("application", d.App.Name),
			zap.String("publisher", d.App.Publisher))
		agentstatus.ReportInstallResult(d.App.Name, "")
	}

	// Tell the portal what became of the approval.
	//
	// Local file first, because that is what the person standing at the Mac
	// is waiting on, and it must not be delayed by a network call.
	a.reportInstallResult(d, err)
}

// reportInstallResult closes the loop on an approval.
func (a *Agent) reportInstallResult(d pendinginstall.MountedDecision, problem error) {
	result := installResultPayload{
		Application: d.App.Name,
		BundleID:    d.App.BundleID,
		Publisher:   d.App.Publisher,
		OSUser:      pendinginstall.ConsoleUser(),
	}
	if problem != nil {
		result.Problem = problem.Error()
	}

	if a.sendResult(result) {
		return
	}

	// Kept, and tried again.
	//
	// This used to be fire and forget: if the agent happened to be between
	// connections, the report was dropped and nothing ever said so. That is
	// not a cosmetic loss — the approval is marked USED by this message, so
	// losing it leaves the approval live for the rest of its window, and
	// somebody can uninstall and reinstall the software all day without
	// asking anybody. The one thing that ends an approval early never
	// arrived.
	a.unreportedMu.Lock()
	a.unreported = append(a.unreported, result)
	a.unreportedMu.Unlock()
	a.logger.Info("Will report the install again when the agent reconnects",
		zap.String("application", result.Application))
}

// sendResult reports one outcome, through the seam a test can replace.
func (a *Agent) sendResult(result installResultPayload) bool {
	if a.sendInstallResultFn != nil {
		return a.sendInstallResultFn(result)
	}
	return a.sendInstallResult(result)
}

// sendInstallResult reports one outcome, and says whether it got out.
func (a *Agent) sendInstallResult(result installResultPayload) bool {
	client := a.grpcSafe()
	if client == nil {
		return false
	}
	payload, err := json.Marshal(result)
	if err != nil {
		// Unreachable in practice — every field is a string — and not worth
		// keeping to retry, because retrying will not make it encodable.
		a.logger.Warn("Could not describe how the install went",
			zap.String("application", result.Application), zap.Error(err))
		return true
	}
	if err := client.SendStatusUpdate(InstallResultDiscriminator, string(payload)); err != nil {
		a.logger.Warn("Could not report how the install went", zap.Error(err))
		return false
	}
	return true
}

// retryUnreportedInstalls sends what could not be sent before.
//
// Called from the scan loop, so it costs nothing while there is nothing to
// send and needs no timer of its own.
func (a *Agent) retryUnreportedInstalls() {
	a.unreportedMu.Lock()
	pending := a.unreported
	a.unreported = nil
	a.unreportedMu.Unlock()

	var stillWaiting []installResultPayload
	for _, result := range pending {
		if !a.sendResult(result) {
			stillWaiting = append(stillWaiting, result)
			continue
		}
		a.logger.Info("Reported an install that had been waiting to be sent",
			zap.String("application", result.Application))
	}

	if len(stillWaiting) > 0 {
		a.unreportedMu.Lock()
		a.unreported = append(stillWaiting, a.unreported...)
		a.unreportedMu.Unlock()
	}
}

// volumeOf is the mount point a bundle path sits in.
//
// The menu bar sends the BUNDLE path, because that is what it shows; the
// decisions are keyed by mount point, because that is what tells one open
// image from another and what disappears when one is ejected.
func volumeOf(bundlePath string) string {
	const prefix = "/Volumes/"
	if !strings.HasPrefix(bundlePath, prefix) {
		return ""
	}
	rest := bundlePath[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return prefix + rest[:i]
	}
	return prefix + rest
}
