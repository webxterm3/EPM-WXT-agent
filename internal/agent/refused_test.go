package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/Yesveer/wxt-agent/internal/apppolicy"
	"github.com/Yesveer/wxt-agent/internal/pendinginstall"
)

const vscodePub = "Developer ID Application: Microsoft Corporation (UBF8T346G9)"

func refusedVSCode(at time.Time) (map[string]refusedInstall, map[string]bool) {
	app := pendinginstall.MountedApp{
		Volume:     "/Volumes/VS Code",
		BundlePath: "/Volumes/VS Code/Visual Studio Code.app",
		Name:       "Visual Studio Code",
		Publisher:  vscodePub,
	}
	return map[string]refusedInstall{
		"/Volumes/VS Code": {
			decision: pendinginstall.MountedDecision{
				App: app, Outcome: pendinginstall.OutcomeNoPolicy,
			},
			at: at, requested: true,
		},
	}, map[string]bool{"/Volumes/VS Code": true}
}

func approvalFor(name, publisher string, until time.Time) *apppolicy.Effective {
	return &apppolicy.Effective{ApprovedInstalls: []apppolicy.ApprovedInstall{
		{Application: name, Publisher: publisher, Until: until},
	}}
}

// THE symptom: approve in the portal, and the Mac still says "needs
// approval".
//
// A refused image has been ejected, so it is gone from the scan and its
// decision is frozen at the moment it was refused. The approval arrives, the
// policy changes, and nothing re-judges the record — so the menu goes on
// reporting a refusal for software that has just been approved.
func TestAnApprovalClearsARefusalThatHasAlreadyBeenEjected(t *testing.T) {
	now := time.Now()
	refused, ejecting := refusedVSCode(now)

	reviseRefused(refused, ejecting, nil,
		approvalFor("Visual Studio Code", vscodePub, now.Add(time.Hour)), now)

	if len(refused) != 0 {
		t.Error("the machine still reports a refusal for software that has " +
			"been approved, so the approval looks like it did nothing")
	}
	if len(ejecting) != 0 {
		t.Error("the eject record survived, so re-opening the image would not " +
			"be asked about again")
	}
}

// Without an approval it stays refused, so the person can still see it and
// still ask.
func TestARefusalSurvivesWhileItIsStillRefused(t *testing.T) {
	now := time.Now()
	refused, ejecting := refusedVSCode(now)

	reviseRefused(refused, ejecting, nil, &apppolicy.Effective{}, now)

	if len(refused) != 1 {
		t.Error("the refusal was forgotten while the software is still refused, " +
			"so the menu row and the way to ask both disappear")
	}
}

// And it ages out, so a menu opened an hour later is not a list of
// everything ever refused.
func TestARefusalIsForgottenAfterItsWindow(t *testing.T) {
	now := time.Now()
	refused, ejecting := refusedVSCode(now.Add(-refusedMemory - time.Minute))

	reviseRefused(refused, ejecting, nil, &apppolicy.Effective{}, now)

	if len(refused) != 0 {
		t.Error("a refusal older than its window is still being shown")
	}
}

// A volume that is still mounted is judged by the scan itself, not here —
// re-judging it from a stale record would fight the live decision.
func TestAMountedVolumeIsLeftToTheScan(t *testing.T) {
	now := time.Now()
	refused, ejecting := refusedVSCode(now)
	mounted := map[string]pendinginstall.MountedDecision{
		"/Volumes/VS Code": {Outcome: pendinginstall.OutcomeNoPolicy},
	}

	reviseRefused(refused, ejecting, mounted,
		approvalFor("Visual Studio Code", vscodePub, now.Add(time.Hour)), now)

	if len(refused) != 1 {
		t.Error("a still-mounted volume was cleared from here instead of being " +
			"left to the scan that owns it")
	}
}

// Audit mode watches; it does not act.
//
// Ejecting somebody's disk image is acting. Neither the eject nor the
// removal grant looked at the mode at all, so a policy saved in AUDIT — the
// mode somebody chooses precisely to find out what it would do — took full
// effect on every Mac in scope. The editor says, in those words, "Matches
// are recorded and projected. Nothing on any machine changes."
func TestAuditModeChangesNothingOnTheMachine(t *testing.T) {
	audit := &apppolicy.Effective{Mode: apppolicy.ModeAudit}
	if audit.Enforcing() {
		t.Error("a policy in audit mode reports itself as enforcing, so disk " +
			"images are ejected and removal rights handed out while the " +
			"editor promises nothing changes")
	}

	enforce := &apppolicy.Effective{Mode: apppolicy.ModeEnforce}
	if !enforce.Enforcing() {
		t.Error("a policy in enforce mode does not enforce")
	}

	// A machine that has never been told anything has not been told to act.
	var none *apppolicy.Effective
	if none.Enforcing() {
		t.Error("a machine with no policy at all reports itself as enforcing")
	}
}

// The agent must never offer itself for removal.
//
// It was listed like any other application, so the menu showed "wxt-agent —
// ask to remove": the thing enforcing policy on the machine, offering the
// people it manages a way to ask for it to be taken off.
func TestTheAgentIsNeverOfferedForRemoval(t *testing.T) {
	for _, own := range []string{
		"/Applications/wxt-agent.app",
		"/usr/local/bin/wxt-agent",
	} {
		if !pendinginstall.IsOwnInstallPath(own) {
			t.Errorf("%s is not recognised as the agent's own, so it will be "+
				"listed for removal like any other application", own)
		}
	}
	if pendinginstall.IsOwnInstallPath("/Applications/Slack.app") {
		t.Error("ordinary software was mistaken for the agent and will never " +
			"be offered for removal")
	}
}

// And the publish loop must actually apply both filters.
func TestOnlyRemovableApplicationsArePublished(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) installedRows", "\nfunc "))

	for _, guard := range []string{"removable[bundle]", "IsOwnInstallPath(bundle)"} {
		if !strings.Contains(body, guard) {
			t.Errorf("installedRows does not check %s, so the menu becomes an "+
				"inventory of the Mac and offers the agent for removal", guard)
		}
	}
}

// Every answer is confirmed before it is shown or acted on — including the
// one that says the software is allowed.
//
// Putting the confirmation after the installable case meant an allowed
// application was never confirmed, so it was never published, so it never
// appeared in the menu at all.
func TestTheConfirmationComesBeforeEveryOtherBranch(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) rescanVolumes", "\nfunc "))

	loop := strings.Index(body, "for volume, d := range next {")
	if loop < 0 {
		t.Fatal("the decision loop is gone")
	}
	settle := strings.Index(body[loop:], "state.settling[volume]")
	installable := strings.Index(body[loop:], "pendinginstall.OutcomeInstallable")
	if settle < 0 || installable < 0 {
		t.Fatal("the loop no longer confirms answers or handles installable software")
	}
	if settle > installable {
		t.Error("the installable case is handled before the answer is confirmed, " +
			"so allowed software is never confirmed, never published, and never " +
			"appears in the menu")
	}

	published := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) publishMounted", "\nfunc "))
	if !strings.Contains(published, "state.confirmed[volume]") {
		t.Error("rows are published without waiting for the answer to be " +
			"confirmed, so the menu asks the wrong question about software " +
			"whose identity had not finished being read")
	}
}

// The agent refusing itself is not a macOS refusal, and must not be
// reported as one.
//
// It went through the same reporting as a real failure, so the log said
// "This Mac will not let applications be made removable" about the agent
// declining its own bundle — and because that message is printed once per
// run, a genuine refusal afterwards was never reported at all. The single
// line that would have answered whether macOS permits a per-application
// entry was spent on the one case that could never get one.
func TestTheAgentsOwnRefusalIsNotReportedAsTheMacsRefusal(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) refreshRemovalGrants", "\nfunc "))

	grant := strings.Index(body, "GrantBundleRemoval(user, bundle)")
	skip := strings.Index(body, "IsOwnInstallPath(bundle)")
	if grant < 0 {
		t.Fatal("removal grants are no longer asked for")
	}
	if skip < 0 || skip > grant {
		t.Error("the agent's own bundle is not skipped before the grant is " +
			"attempted, so its own refusal is reported as the Mac's and " +
			"silences the one that matters")
	}
}
