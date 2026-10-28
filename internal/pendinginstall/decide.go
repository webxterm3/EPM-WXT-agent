package pendinginstall

import (
	"time"

	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// What kind of thing is sitting in a mounted image.
const (
	// KindBundle is an application somebody would drag across. The empty
	// string, so every MountedApp built before packages existed still reads
	// as what it is.
	KindBundle = ""
	// KindPackage is an installer package: a program that runs as root and
	// may do anything, which is why its signature is the whole of the trust
	// decision rather than a label on it.
	KindPackage = "package"
)

// Outcome is what the agent will do about a downloaded installer, and why.
//
// Five answers rather than a boolean, because they send a person to five
// different places. "Nothing happened" is the one outcome this must never
// produce: an installer sitting on somebody's disk with no explanation is the
// situation the feature exists to end.
type Outcome string

const (
	// OutcomeInstallable: policy allows it and the operating system vouches
	// for who made it, so the drag is allowed to succeed.
	OutcomeInstallable Outcome = "installable"

	// OutcomeBlocked: policy forbids this software. The person is told, and
	// offered the approval route rather than left to wonder.
	OutcomeBlocked Outcome = "blocked"

	// OutcomeUnverified: nothing vouches for the file.
	//
	// Deliberately NOT installable even when a policy rule appears to allow
	// it. Without a verified signature the only identity the file has is its
	// NAME, and matching a rule against a name is what turns this feature
	// into a way to run anything as root: policy says Visual Studio Code may
	// be installed, somebody renames their own package to VSCode.pkg, and the
	// agent installs it with full privilege.
	OutcomeUnverified Outcome = "unverified"

	// OutcomeNoPolicy: no rule mentions this software. Listed rather than
	// hidden, so somebody can ask about it.
	OutcomeNoPolicy Outcome = "no-policy"
)

// MountedDecision is a disk image somebody opened, and what will happen when
// they drag what is inside it.
type MountedDecision struct {
	App MountedApp

	Outcome Outcome
	Rule    string
	Policy  string
	Reason  string

	// Own marks this product's own installer.
	//
	// It is allowed, so that installing or upgrading the agent never needs a
	// password — but it is not SHOWN. The agent is already running: offering
	// to install it is offering to do something it does for itself, and the
	// offer reappeared every time somebody left the disk image mounted.
	Own bool
}

// DecideMounted works out what to do about an application somebody is about
// to drag out of a disk image.
//
// The identity comes from the bundle itself — its own name, bundle id and
// signature — so the same rule that matches the installed application
// matches its installer, with no second way of saying the same thing.
func DecideMounted(app MountedApp, eff *apppolicy.Effective) MountedDecision {
	d := MountedDecision{App: app}

	// Our own installer, before anything else is consulted.
	//
	// Deliberately above the policy — including above the no-policy case —
	// because the machines that most need this are the ones with no policy:
	// a fresh enrolment, a machine whose policy was deleted, one that has
	// not connected yet. Expressing the exemption as a policy ROW instead
	// would fail on exactly those, and the failure is self-sealing: the way
	// out of a refused agent install is an approval request, and it is the
	// agent that raises them.
	//
	// It is an identity check, not a name check — see IsOwnPackage.
	if IsOwnPackage(app) {
		d.Own = true
		d.Outcome = OutcomeInstallable
		d.Reason = "This is the management agent itself, signed by the same " +
			"certificate as the copy already running. It installs without a password."
		return d
	}

	if eff == nil {
		d.Outcome = OutcomeNoPolicy
		d.Reason = "No application policy has reached this machine yet."
		return d
	}

	// Judged at the path the application WOULD live at, not the one inside
	// the disk image it is sitting in.
	//
	// The question at mount time is whether this software may be on this
	// machine, and a rule written against a path means the installed path —
	// /Applications/Claude.app — which is also what the enforcement pass and
	// the removal pass both judge against. Evaluating /Volumes/Claude/
	// Claude.app made every path rule behave differently before and after
	// the install: an application an operator had explicitly allowed was
	// reported as not covered by any rule, so installing it asked for an
	// approval nobody should have had to give.
	verdict := eff.Evaluate(apppolicy.Program{
		Name:      app.Name,
		Publisher: app.Publisher,
		Path:      InstalledPathFor(app.Name),
		BundleID:  app.BundleID,
	})
	d.Rule, d.Policy = verdict.Rule, verdict.PolicyName

	// An administrator may have approved this one, usually in answer to a
	// request raised from this machine when it was refused before.
	//
	// Checked BEFORE the policy verdict, not inside the block branch.
	//
	// It used to be inside it, and that quietly made the whole approval
	// round-trip useless for the ordinary case: software nobody has written
	// a rule about does not reach the block branch — it falls through to
	// no-policy — so an approver could say yes, the exception would be
	// delivered to the machine, and the agent would go on refusing it with
	// no sign that anything had been approved at all.
	//
	// The signature is still required. An approval names an application an
	// approver looked at; without a verified publisher the only identity
	// this bundle has is the folder name inside the image, and an unsigned
	// lookalike would inherit somebody else's permission. That is also why
	// hoisting this is safe: an unverified bundle has no Publisher, so it
	// cannot be approved into existence here.
	// A RULE that blocks beats any approval.
	//
	// This used to be the other way round, on the reasoning that an approval
	// is a deliberate exception and overriding a block is the whole point of
	// the request route. In practice it produced a policy nobody could rely
	// on: an administrator wrote a rule forbidding an application, the
	// machine reported it as allowed because somebody had approved it
	// earlier, and the rule looked broken. A standing rule is a decision
	// about every machine; an approval is one person's answer to one ask,
	// and it must not quietly outrank it.
	//
	// The portal refuses to approve a request for software a rule blocks, so
	// the two ends agree: to allow it, the rule has to change.
	blockedByRule := verdict.Action == apppolicy.ActionBlock && verdict.FromRule

	if !blockedByRule && app.Publisher != "" &&
		eff.InstallApproved(app.Name, app.BundleID, app.Publisher, time.Now()) {
		d.Outcome = OutcomeInstallable
		d.Reason = app.Name + " was approved for this machine."
		return d
	}

	switch {
	case verdict.Action == apppolicy.ActionBlock:
		d.Outcome = OutcomeBlocked
		// Said plainly, and without the mechanics.
		//
		// The person reading this is standing at the Mac. They cannot change
		// a policy rule and have no use for being told that an approval
		// would not override one — that is the approver's problem, and the
		// portal is where it is explained, to somebody who can act on it.
		// Here it only reads as the machine arguing.
		d.Reason = "Your organisation does not allow " + app.Name +
			" to be installed on this Mac."

	case app.Publisher == "":
		// Without a verified signature the only identity this has is the
		// folder name inside the image, and anybody can name a folder.
		// Tested BEFORE the no-policy branch, not after it.
		//
		// The other order let an unsigned bundle fall through to no-policy,
		// which IS requestable — so somebody could raise an approval for
		// something no approval can ever redeem: the signature is what is
		// missing, and InstallApproved refuses without a publisher however
		// many people say yes. They asked, somebody approved, and it stayed
		// refused with nothing explaining the difference.
		d.Outcome = OutcomeUnverified
		d.Reason = app.Name + " is not signed, or its signature does not check out, " +
			"so there is nothing to confirm it is really what it claims to be."

	case !verdict.FromRule:
		// A catch-all allow means "nobody has thought about this one", which
		// is not permission to put it on the machine without a password.
		d.Outcome = OutcomeNoPolicy
		d.Reason = "No policy rule covers " + app.Name + ", so it has not been approved."

	case verdict.Action == apppolicy.ActionAllow:
		d.Outcome = OutcomeInstallable
		// Not "drag it": whether the drag works depends on an
		// access-control entry macOS may refuse to write, and the menu says
		// which it is. Promising a gesture here that then meets the
		// administrator password sheet is the one thing this must not do.
		d.Reason = app.Name + " is allowed by the rule \"" + verdict.Rule +
			"\". It installs without an administrator password."

	default:
		// Any other verdict from a rule grants nothing here.
		//
		// This used to be the installable branch, which made an ELEVATE rule
		// a silent password-free install grant: elevation is not implemented
		// on any platform, so such a rule does nothing at launch — and it
		// fell through to here and let the application be installed without
		// anybody being asked. An action that visibly does nothing was the
		// most permissive thing in the editor.
		//
		// Only an explicit allow installs. Anything else is treated as not
		// decided, which is askable — so the route out is an approval rather
		// than a dead end.
		d.Outcome = OutcomeNoPolicy
		d.Reason = "The rule covering " + app.Name + " does not permit it to " +
			"be installed, so it has not been approved."
	}
	return d
}

// Requestable reports whether an approver could change this answer.
//
// Blocked and not-covered both can: one is a rule saying no, the other is
// nobody having decided, and in a default-deny estate the second is the
// common case — most software nobody has written a rule about. Somebody who
// needs it has to be able to ask, or a default-deny policy means filing a
// ticket by hand for every application anybody has ever needed.
//
// Unverified cannot. The problem there is the signature, and an administrator
// saying yes would not change it — the bundle would still be something the
// operating system cannot vouch for, and approving it would mean approving
// whatever happened to be in the image.
func (o Outcome) Requestable() bool {
	return o == OutcomeBlocked || o == OutcomeNoPolicy
}
