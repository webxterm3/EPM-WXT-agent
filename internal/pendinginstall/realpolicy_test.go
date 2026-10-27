package pendinginstall

import (
	"strings"
	"testing"
	"time"

	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// The three answers the product gives, pinned against a policy written the
// way the portal writes one.
//
// Built from two real policies, field for field as the editor saved them —
// an Allow rule for Visual Studio Code and a Block rule for Claude, both
// matching on name AND publisher AND path AND bundle id at once, with the
// policy default left at Allow.
//
// It is here because every one of those fields has been a bug: the path was
// judged at /Volumes instead of /Applications so Allow rules did not match,
// an approval used to override a Block rule, and a catch-all Allow has to
// stay "nobody has decided" rather than becoming permission. A unit test per
// field would not have caught any of them, because each needs the others to
// be right at the same time.

func containsValue(v string) apppolicy.StringMatch {
	return apppolicy.StringMatch{Op: "contains", Values: []string{v}}
}

func exactlyValue(v string) apppolicy.StringMatch {
	return apppolicy.StringMatch{Op: "equals", Values: []string{v}}
}

func portalWrittenPolicy() *apppolicy.Effective {
	return &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce,
		// "If no rule matches: Allow", as the editor offers it.
		DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{
			{
				Rule: apppolicy.Rule{
					ID: "r1", Name: "Allow Visual Studio Code", Enabled: true,
					Action: apppolicy.ActionAllow,
					Match: apppolicy.MatchCriteria{
						AppName:   exactlyValue("Visual Studio Code"),
						Publisher: containsValue("UBF8T346G9"),
						FilePath:  containsValue("/Applications/Visual Studio Code.app"),
						BundleID:  exactlyValue("com.microsoft.VSCode"),
					},
				},
				PolicyName: "Visual Studio Code", Mode: apppolicy.ModeEnforce, RemoveBlocked: true,
			},
			{
				Rule: apppolicy.Rule{
					ID: "r2", Name: "Block Claude", Enabled: true,
					Action: apppolicy.ActionBlock,
					Match: apppolicy.MatchCriteria{
						AppName:   exactlyValue("Claude"),
						Publisher: containsValue("Q6L2SF6YDW"),
						FilePath:  containsValue("/Applications/Claude.app"),
						BundleID:  exactlyValue("com.anthropic.claudefordesktop"),
					},
				},
				PolicyName: "Claude", Mode: apppolicy.ModeEnforce, RemoveBlocked: true,
			},
		},
	}
}

func mounted(name, publisher, bundleID string) MountedApp {
	return MountedApp{
		Volume:     "/Volumes/" + name,
		BundlePath: "/Volumes/" + name + "/" + name + ".app",
		Name:       name, Publisher: publisher, BundleID: bundleID,
	}
}

// Allowed by a rule: it installs, with no password.
func TestSoftwareAnAllowRuleNamesInstalls(t *testing.T) {
	d := DecideMounted(mounted("Visual Studio Code",
		"Developer ID Application: Microsoft Corporation (UBF8T346G9)",
		"com.microsoft.VSCode"), portalWrittenPolicy())

	if d.Outcome != OutcomeInstallable {
		t.Fatalf("outcome %q (%s) — software an operator explicitly allowed "+
			"does not install", d.Outcome, d.Reason)
	}
	if strings.Contains(strings.ToLower(d.Reason), "drag") {
		t.Errorf("reason %q promises a drag, which needs an access-control "+
			"entry macOS may refuse to write", d.Reason)
	}
}

// Blocked by a rule: refused, and no approval can change it.
func TestSoftwareABlockRuleNamesIsRefusedAndCannotBeApprovedAway(t *testing.T) {
	app := mounted("Claude",
		"Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
		"com.anthropic.claudefordesktop")

	eff := portalWrittenPolicy()
	d := DecideMounted(app, eff)
	if d.Outcome != OutcomeBlocked {
		t.Fatalf("outcome %q (%s), want %q", d.Outcome, d.Reason, OutcomeBlocked)
	}
	// The rule is recorded on the decision, for the log and the portal. The
	// message shown at the Mac is deliberately plain — somebody standing
	// there cannot change a policy rule, and telling them an approval would
	// not override one only reads as the machine arguing.
	if d.Rule != "Block Claude" {
		t.Errorf("the decision records rule %q, so nothing can say which rule "+
			"refused it", d.Rule)
	}

	// Even with a live approval sitting against it.
	eff.ApprovedInstalls = []apppolicy.ApprovedInstall{{
		Application: "Claude",
		Publisher:   "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)",
		Until:       time.Now().Add(time.Hour),
	}}
	if again := DecideMounted(app, eff); again.Outcome == OutcomeInstallable {
		t.Error("an approval overrode a rule that forbids it, so the rule an " +
			"administrator wrote decides nothing")
	}
}

// Named by no rule: askable, whatever the policy default says.
//
// A catch-all Allow means "nobody has thought about this one", which is not
// the same as permission to put it on the machine without anybody deciding.
func TestSoftwareNoRuleNamesAsksForApproval(t *testing.T) {
	d := DecideMounted(mounted("Slack",
		"Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)",
		"com.tinyspeck.slackmacgap"), portalWrittenPolicy())

	if d.Outcome != OutcomeNoPolicy {
		t.Fatalf("outcome %q (%s), want %q", d.Outcome, d.Reason, OutcomeNoPolicy)
	}
	if !d.Outcome.Requestable() {
		t.Error("software nobody has decided about cannot even be asked for")
	}
}
