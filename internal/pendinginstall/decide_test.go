package pendinginstall

import (
	"strings"
	"testing"
	"time"

	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

func allowByName(name string) *apppolicy.Effective {
	return &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{{
			PolicyName: "Approved software",
			Rule: apppolicy.Rule{
				Name: "Allow " + name, Enabled: true, Action: apppolicy.ActionAllow,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpEquals, Values: []string{name}},
				},
			},
		}},
	}
}

func blockByName(name string) *apppolicy.Effective {
	return &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{{
			PolicyName: "Not approved",
			Rule: apppolicy.Rule{
				Name: "Block " + name, Enabled: true, Action: apppolicy.ActionBlock,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpEquals, Values: []string{name}},
				},
			},
		}},
	}
}

// THE rule this feature stands on.
//
// A disk image's contents are whatever its author put there, and the folder
// inside it can be called anything. Without a verified signature, approving
// on the NAME means somebody builds an image containing their own
// application, calls the folder "Visual Studio Code", and the agent opens
// /Applications for them to drag it in.
//
// A rule that allows by name is the easy one to write — an administrator
// types the name they know — so the signature check has to hold underneath
// it. A rule that allows by publisher is safe on its own: an unsigned bundle
// has no publisher and matches nothing.
func TestAnUnsignedBundleNeverOpensTheWindow(t *testing.T) {
	impostor := MountedApp{
		Volume: "/Volumes/VSCode", BundlePath: "/Volumes/VSCode/Visual Studio Code.app",
		Name: "Visual Studio Code", Publisher: "",
	}

	d := DecideMounted(impostor, allowByName("Visual Studio Code"))
	if d.Outcome == OutcomeInstallable {
		t.Fatal("an unsigned bundle was approved because of what its folder was " +
			"called — this is the hole the signature check exists to close")
	}
	if d.Outcome != OutcomeUnverified {
		t.Errorf("outcome %q, want %q", d.Outcome, OutcomeUnverified)
	}
}

func TestASignedApprovedApplicationOpensTheWindow(t *testing.T) {
	real := MountedApp{
		Volume: "/Volumes/VSCode", BundlePath: "/Volumes/VSCode/Visual Studio Code.app",
		Name:      "Visual Studio Code",
		BundleID:  "com.microsoft.VSCode",
		Publisher: "Developer ID Application: Microsoft Corporation (UBF8T346G9)",
	}

	d := DecideMounted(real, allowByName("Visual Studio Code"))
	if d.Outcome != OutcomeInstallable {
		t.Fatalf("outcome %q (%s), want %q", d.Outcome, d.Reason, OutcomeInstallable)
	}
	if d.Rule == "" || d.Policy == "" {
		t.Error("the decision does not name what approved it")
	}
	// The sentence is read by somebody deciding whether to drag.
	if !strings.Contains(d.Reason, "password") {
		t.Errorf("reason %q does not tell them what will happen", d.Reason)
	}
}

// Blocking is decided before anything about signatures. Telling somebody "we
// cannot verify this" about software the organisation has banned sends them
// off to find a properly signed copy of the thing they may not have.
func TestABlockedApplicationIsReportedAsBlocked(t *testing.T) {
	for _, publisher := range []string{
		"Developer ID Application: Anthropic (ABC123DEF4)",
		"", // unsigned
	} {
		d := DecideMounted(MountedApp{Name: "Claude", Publisher: publisher}, blockByName("Claude"))
		if d.Outcome != OutcomeBlocked {
			t.Errorf("publisher=%q gave %q, want %q", publisher, d.Outcome, OutcomeBlocked)
		}
		if !strings.Contains(d.Reason, "Claude") {
			t.Errorf("reason %q does not name the application", d.Reason)
		}
	}
}

// A catch-all allow means "nobody has thought about this one". That is not
// permission to put it on the machine without a password.
func TestThePolicyDefaultNeverOpensTheWindow(t *testing.T) {
	eff := &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
	d := DecideMounted(MountedApp{
		Name: "Anything", Publisher: "Developer ID Application: Somebody (XXXXXXXXXX)",
	}, eff)

	if d.Outcome == OutcomeInstallable {
		t.Fatal("the policy's catch-all allow was read as approval to open /Applications")
	}
	if d.Outcome != OutcomeNoPolicy {
		t.Errorf("outcome %q, want %q", d.Outcome, OutcomeNoPolicy)
	}
}

func TestAMachineWithNoPolicyYetDoesNotGuess(t *testing.T) {
	d := DecideMounted(MountedApp{Name: "VSCode", Publisher: "Developer ID Application: MS (X)"}, nil)
	if d.Outcome != OutcomeNoPolicy {
		t.Errorf("outcome %q, want %q", d.Outcome, OutcomeNoPolicy)
	}
}

// Every outcome carries a sentence. An image somebody opened that produces no
// explanation is the situation this feature exists to end.
func TestEveryOutcomeExplainsItself(t *testing.T) {
	signed := "Developer ID Application: Microsoft Corporation (UBF8T346G9)"
	for _, c := range []struct {
		eff *apppolicy.Effective
		app MountedApp
	}{
		{allowByName("A"), MountedApp{Name: "A", Publisher: signed}},
		{blockByName("A"), MountedApp{Name: "A", Publisher: signed}},
		{allowByName("A"), MountedApp{Name: "A"}},
		{&apppolicy.Effective{Mode: apppolicy.ModeEnforce}, MountedApp{Name: "A", Publisher: signed}},
		{nil, MountedApp{Name: "A"}},
	} {
		d := DecideMounted(c.app, c.eff)
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("outcome %q carries no reason", d.Outcome)
		}
	}
}

func approvedUntil(name, publisher string, until time.Time) *apppolicy.Effective {
	eff := blockByName(name)
	eff.ApprovedInstalls = []apppolicy.ApprovedInstall{
		{Application: name, Publisher: publisher, Until: until},
	}
	return eff
}

// A RULE that blocks beats any approval.
//
// It used to be the other way round, on the reasoning that an approval is a
// deliberate exception and overriding a block is the point of the request
// route. In practice that produced a policy nobody could rely on: an
// administrator wrote a rule forbidding an application, the machine reported
// it as allowed because somebody had approved it earlier, and the rule
// looked broken. A standing rule is a decision about every machine; an
// approval is one person's answer to one ask.
//
// The portal refuses to approve a request for software a rule blocks, so
// both ends say the same thing: to allow it, the rule has to change.
func TestARuleThatBlocksBeatsAnApproval(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	app := MountedApp{Name: "Claude", Publisher: pub}

	d := DecideMounted(app, approvedUntil("Claude", pub, time.Now().Add(time.Hour)))
	if d.Outcome == OutcomeInstallable {
		t.Fatalf("an approval overrode a rule that forbids %s: %s", app.Name, d.Reason)
	}

	// The decision carries which rule decided, even though the message
	// shown at the Mac deliberately does not: the person standing there
	// cannot change a rule, and the name is for the log and the portal.
	if d.Rule == "" {
		t.Error("the decision does not record which rule refused it, so the " +
			"log cannot say why either")
	}
}

// And the case an approval IS for: software no rule mentions.
//
// That is the ordinary answer in a default-deny estate, and the one somebody
// most needs a way through. Taking it away as well would leave the request
// route with nothing to do.
func TestAnApprovalStillRescuesSoftwareNoRuleMentions(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	app := MountedApp{Name: "Claude", Publisher: pub}

	eff := &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce,
		ApprovedInstalls: []apppolicy.ApprovedInstall{
			{Application: "Claude", Publisher: pub, Until: time.Now().Add(time.Hour)},
		},
	}

	d := DecideMounted(app, eff)
	if d.Outcome != OutcomeInstallable {
		t.Fatalf("outcome %q (%s), want %q", d.Outcome, d.Reason, OutcomeInstallable)
	}
	if !strings.Contains(d.Reason, "approved") {
		t.Errorf("reason %q does not say an approval is why", d.Reason)
	}
}

// An approval that has run out is a block again. Without this, one click
// would be a permanent policy change made by whoever happened to make it.
func TestAnExpiredApprovalBlocksAgain(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	app := MountedApp{Name: "Claude", Publisher: pub}

	d := DecideMounted(app, approvedUntil("Claude", pub, time.Now().Add(-time.Minute)))
	if d.Outcome != OutcomeBlocked {
		t.Errorf("outcome %q, want %q — an approval with no end is a policy change "+
			"made by one click", d.Outcome, OutcomeBlocked)
	}
}

// An approval names an application an approver looked at. Without a verified
// signature the only identity a bundle has is the folder name inside the
// image, so an unsigned lookalike would inherit somebody else's permission —
// which is the exact trick this whole feature has to be proof against.
func TestAnUnsignedLookalikeCannotInheritAnApproval(t *testing.T) {
	impostor := MountedApp{Name: "Claude", Publisher: ""}

	t.Run("approval records a publisher", func(t *testing.T) {
		const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
		d := DecideMounted(impostor, approvedUntil("Claude", pub, time.Now().Add(time.Hour)))
		if d.Outcome == OutcomeInstallable {
			t.Fatal("an unsigned bundle claimed an approval granted for the real one")
		}
	})

	// The case that actually exercises the signature guard.
	//
	// An approval raised before publishers were recorded carries only a NAME.
	// Nothing in the matching can then tell the real application from a
	// folder somebody called the same, so the only thing standing between an
	// unsigned bundle and /Applications is the requirement that it be signed
	// at all.
	t.Run("approval records only a name", func(t *testing.T) {
		d := DecideMounted(impostor, approvedUntil("Claude", "", time.Now().Add(time.Hour)))
		if d.Outcome == OutcomeInstallable {
			t.Fatal("an unsigned bundle inherited a name-only approval — anybody " +
				"could build an image with a folder called Claude.app and have it " +
				"dragged into /Applications")
		}
	})
}

// A publisher recorded on the approval has to match. Somebody else's signed
// application of the same name is a different application.
func TestADifferentPublisherCannotClaimTheApproval(t *testing.T) {
	theirs := MountedApp{
		Name:      "Claude",
		Publisher: "Developer ID Application: Somebody Else (ZZZZZZZZZZ)",
	}
	d := DecideMounted(theirs, approvedUntil(
		"Claude", "Developer ID Application: Anthropic (ABC123DEF4)",
		time.Now().Add(time.Hour)))

	if d.Outcome == OutcomeInstallable {
		t.Fatal("a differently-signed application claimed the approval")
	}
}

// In a default-deny estate most software is not covered by any rule, so
// "nobody has decided" is the common answer rather than the rare one. If only
// explicitly blocked applications could be asked about, every other one would
// mean filing a ticket by hand.
func TestSoftwareNobodyHasDecidedAboutCanStillBeAskedFor(t *testing.T) {
	if !OutcomeNoPolicy.Requestable() {
		t.Error("software no rule covers cannot be asked about — in a default-deny " +
			"estate that is most of it")
	}
}

// A rule is an administrator having already answered this for the whole
// estate, and the portal refuses to approve an exception to one. A request
// raised against it was a dead letter: the person was told it had been sent,
// an approver saw a row they could not say yes to, and the answer never
// changed. The agent says so at the Mac instead.
func TestSoftwareARuleForbidsIsNotAskedAbout(t *testing.T) {
	if OutcomeBlocked.Requestable() {
		t.Error("a rule block offered an approval route; the portal will not " +
			"approve one, so the request can never be redeemed")
	}
	if !OutcomeBlocked.BlockedByPolicy() {
		t.Error("a rule block is not reported as blocked by policy, so nothing " +
			"can word it differently from a missing signature")
	}
	// The two refusals must stay distinguishable. Telling somebody their
	// organisation forbids an application, when the real problem is that it
	// is unsigned, sends them to argue with an administrator who has never
	// heard of it.
	if OutcomeUnverified.BlockedByPolicy() {
		t.Error("an unsigned bundle is reported as blocked by policy")
	}
}

// THE trap in making a block unaskable.
//
// A default-deny estate evaluates to "block" for everything nobody has
// written a rule about — which is nearly every application. Both kinds of
// block produced OutcomeBlocked once, and if they are ever merged again this
// is what breaks: every default-deny estate silently loses its approval
// route, with the menu telling people to go and get a rule changed that
// nobody ever wrote.
func TestADefaultDenyCatchAllIsStillSomethingYouCanAskAbout(t *testing.T) {
	signed := MountedApp{
		Volume: "/Volumes/Slack", BundlePath: "/Volumes/Slack/Slack.app",
		Name: "Slack", Publisher: "Developer ID Application: Slack Technologies",
	}

	denyAll := &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionBlock,
	}
	d := DecideMounted(signed, denyAll)

	if d.Outcome.BlockedByPolicy() {
		t.Fatal("a default-deny catch-all was reported as a rule block; nobody " +
			"wrote a rule about this application, so there is nothing to go and change")
	}
	if !d.Outcome.Requestable() {
		t.Fatal("software in a default-deny estate could not be asked about — " +
			"that is nearly every application, and the approval route is gone")
	}

	// And the explicit rule, for contrast, from the same starting point.
	if !DecideMounted(signed, blockByName("Slack")).Outcome.BlockedByPolicy() {
		t.Fatal("an explicit block rule was not reported as a rule block")
	}
}

// The problem with an unverified bundle is the signature, and an approval
// would not change it. Offering the route would collect approvals that cannot
// mean anything — somebody would be approving whatever happened to be in the
// image.
func TestAnUnverifiableBundleCannotBeApprovedIntoExistence(t *testing.T) {
	if OutcomeUnverified.Requestable() {
		t.Error("an unsigned bundle offered an approval route; an administrator " +
			"saying yes would not make it verifiable")
	}
	if OutcomeInstallable.Requestable() {
		t.Error("something already allowed offered an approval route")
	}
}

// approvedWithNoRule is the ordinary case in a default-deny estate: nobody
// has written a rule about this software, somebody asked for it, and an
// approver said yes.
func approvedWithNoRule(name, publisher string, until time.Time) *apppolicy.Effective {
	eff := &apppolicy.Effective{
		ApprovedInstalls: []apppolicy.ApprovedInstall{
			{Application: name, Publisher: publisher, Until: until},
		},
	}
	return eff
}

// THE case the approval round-trip exists for, and the one it did not cover.
//
// Most software has no rule written about it — that is what "default deny"
// means in practice — so almost every request an approver ever sees is for
// something that resolves to no-policy rather than to blocked. The approval
// check used to live inside the blocked branch, which that software never
// reaches. So the request was raised, the approver said yes, the exception
// was delivered to the machine, and the agent went on refusing it. Nothing
// anywhere reported a problem: from the portal it looked approved, and from
// the Mac it looked like nobody had answered.
func TestApprovingSoftwareNobodyWroteARuleAboutActuallyWorks(t *testing.T) {
	const pub = "Developer ID Application: Microsoft Corporation (UBF8T346G9)"
	app := MountedApp{
		Volume:     "/Volumes/Visual Studio Code",
		BundlePath: "/Volumes/Visual Studio Code/Visual Studio Code.app",
		Name:       "Visual Studio Code",
		Publisher:  pub,
	}

	eff := approvedWithNoRule("Visual Studio Code", pub, time.Now().Add(time.Hour))
	d := DecideMounted(app, eff)

	if d.Outcome != OutcomeInstallable {
		t.Fatalf("an approver said yes and the agent still answers %q (%s)", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "approved") {
		t.Errorf("reason %q does not tell the person an approval is why it now works", d.Reason)
	}
}

// And the approval must still expire for unlisted software, exactly as it
// does for blocked software. Otherwise one click is a permanent carve-out
// for everything nobody has written a rule about — which is most things.
func TestAnExpiredApprovalForUnlistedSoftwareStopsWorking(t *testing.T) {
	const pub = "Developer ID Application: Microsoft Corporation (UBF8T346G9)"
	app := MountedApp{Name: "Visual Studio Code", Publisher: pub}

	eff := approvedWithNoRule("Visual Studio Code", pub, time.Now().Add(-time.Minute))
	d := DecideMounted(app, eff)

	if d.Outcome == OutcomeInstallable {
		t.Fatalf("an approval that ran out still installs: %s", d.Reason)
	}
	if !d.Outcome.Requestable() {
		t.Errorf("outcome %q cannot be asked about again, so the person is stuck", d.Outcome)
	}
}

// An unsigned bundle must not be approvable even when no rule mentions it.
// This is the same guard as the blocked case, now that the check applies to
// both — hoisting it would be a hole if it had skipped the signature test.
func TestAnUnsignedBundleCannotBeApprovedWhenNoRuleMentionsIt(t *testing.T) {
	const pub = "Developer ID Application: Microsoft Corporation (UBF8T346G9)"
	impostor := MountedApp{
		Volume:     "/Volumes/VSCode",
		BundlePath: "/Volumes/VSCode/Visual Studio Code.app",
		Name:       "Visual Studio Code",
		Publisher:  "", // nothing vouches for it
	}

	eff := approvedWithNoRule("Visual Studio Code", pub, time.Now().Add(time.Hour))
	d := DecideMounted(impostor, eff)

	if d.Outcome == OutcomeInstallable {
		t.Fatalf("an unsigned bundle named %q inherited an approval meant for "+
			"the real thing: %s", impostor.Name, d.Reason)
	}
}

// An unsigned bundle must not be able to raise a request nothing can redeem.
//
// It used to fall through to no-policy, which IS requestable — so somebody
// could ask, an approver could say yes, and it would stay refused: the
// signature is what is missing, and InstallApproved refuses without a
// publisher however many people agree. From both ends it looked like the
// approval had simply been ignored.
func TestAnUnsignedBundleIsNotOfferedARouteThatLeadsNowhere(t *testing.T) {
	unsigned := MountedApp{
		Volume:     "/Volumes/Thing",
		BundlePath: "/Volumes/Thing/Thing.app",
		Name:       "Thing",
		Publisher:  "",
	}

	// No rule mentions it — the case that used to produce no-policy.
	d := DecideMounted(unsigned, &apppolicy.Effective{})
	if d.Outcome != OutcomeUnverified {
		t.Fatalf("outcome %q, want %q", d.Outcome, OutcomeUnverified)
	}
	if d.Outcome.Requestable() {
		t.Error("an unsigned bundle is still offered an approval route that " +
			"no approval can satisfy")
	}
}

// Signed software nobody has written a rule about is still askable — that is
// the ordinary case and must not have been caught by the reordering.
func TestSignedSoftwareWithNoRuleIsStillAskable(t *testing.T) {
	app := MountedApp{
		Name:      "Visual Studio Code",
		Publisher: "Developer ID Application: Microsoft Corporation (UBF8T346G9)",
	}
	d := DecideMounted(app, &apppolicy.Effective{})
	if d.Outcome != OutcomeNoPolicy {
		t.Fatalf("outcome %q, want %q", d.Outcome, OutcomeNoPolicy)
	}
	if !d.Outcome.Requestable() {
		t.Error("signed software nobody has decided about can no longer be asked for")
	}
}

// An action that does nothing must not be the most permissive thing in the
// editor.
//
// Elevation is not implemented on any platform — platformElevator returns
// unsupportedElevator on macOS, on Windows and everywhere else — so an
// elevate rule does nothing at launch. It used to fall through to the
// installable branch, which made it a silent password-free INSTALL grant:
// the one action whose own hint admitted it had no effect was quietly the
// only one that let software onto a machine unasked.
func TestAnElevateRuleDoesNotQuietlyPermitInstalling(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	app := MountedApp{Name: "Claude", Publisher: pub}

	eff := &apppolicy.Effective{Mode: apppolicy.ModeEnforce, Rules: []apppolicy.EffectiveRule{{
		Rule: apppolicy.Rule{
			ID: "e1", Name: "run Claude elevated", Enabled: true,
			Action: apppolicy.ActionElevate,
			Match: apppolicy.MatchCriteria{
				AppName: apppolicy.StringMatch{Op: "equals", Values: []string{"Claude"}},
			},
		},
		PolicyName: "test", Mode: apppolicy.ModeEnforce,
	}}}

	d := DecideMounted(app, eff)
	if d.Outcome == OutcomeInstallable {
		t.Fatalf("an elevate rule let %s be installed without anybody being "+
			"asked: %s", app.Name, d.Reason)
	}
	// And it must still be askable, so the route out is an approval rather
	// than a dead end.
	if !d.Outcome.Requestable() {
		t.Errorf("outcome %q offers no way forward at all", d.Outcome)
	}
}

// An explicit allow still installs — that is what allow is for.
func TestAnAllowRuleStillPermitsInstalling(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	app := MountedApp{Name: "Claude", Publisher: pub}

	if d := DecideMounted(app, allowByName("Claude")); d.Outcome != OutcomeInstallable {
		t.Fatalf("an allow rule answers %q (%s)", d.Outcome, d.Reason)
	}
}

// A rule written against a path must mean the same thing before and after
// the install.
//
// It did not: the mount decision judged /Volumes/Claude/Claude.app while the
// enforcement and removal passes judged /Applications/Claude.app. So an
// operator who allowed an application by path saw it reported as covered by
// no rule at install time — "allowed software is asking for approval" — and
// correctly allowed once it was already on the machine.
func TestAPathRuleMeansTheInstalledPath(t *testing.T) {
	app := MountedApp{
		Volume:     "/Volumes/Claude",
		BundlePath: "/Volumes/Claude/Claude.app",
		Name:       "Claude",
		Publisher:  "Developer ID Application: Anthropic (ABC123DEF4)",
	}

	byPath := &apppolicy.Effective{Mode: apppolicy.ModeEnforce, Rules: []apppolicy.EffectiveRule{{
		Rule: apppolicy.Rule{
			ID: "p1", Name: "Claude is allowed", Enabled: true,
			Action: apppolicy.ActionAllow,
			Match: apppolicy.MatchCriteria{
				FilePath: apppolicy.StringMatch{
					Op: "equals", Values: []string{"/Applications/Claude.app"},
				},
			},
		},
		PolicyName: "test", Mode: apppolicy.ModeEnforce,
	}}}

	d := DecideMounted(app, byPath)
	if d.Outcome != OutcomeInstallable {
		t.Fatalf("an application allowed by path answers %q (%s) — installing "+
			"software an operator explicitly allowed asks for an approval",
			d.Outcome, d.Reason)
	}
}
