package apppolicy

import "testing"

func elevateRule(name string) *Effective {
	return &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{{
			PolicyName: "Elevation", Mode: ModeEnforce,
			Rule: Rule{
				Name: "Let " + name + " elevate", Enabled: true, Action: ActionElevate,
				Match: MatchCriteria{AppName: StringMatch{Op: OpEquals, Values: []string{name}}},
			},
		}},
	}
}

func TestARuleCanGrantElevation(t *testing.T) {
	d := elevateRule("Installer").Evaluate(Program{Name: "Installer"})
	if !d.Elevates() {
		t.Fatalf("a matching elevate rule did not grant elevation: %+v", d)
	}
}

// The single most dangerous thing this engine could get wrong.
//
// A policy whose DEFAULT action is elevate would mean every application the
// rules do not mention runs with administrator rights — the opposite of least
// privilege, delivered by the product that exists to enforce it. The backend
// refuses to store such a default; this is the second lock on the same door,
// and it holds even for a policy that arrives hand-edited or from an older
// backend that had no such check.
func TestTheDefaultActionCanNeverElevate(t *testing.T) {
	eff := &Effective{Mode: ModeEnforce, DefaultAction: ActionElevate}

	d := eff.Evaluate(Program{Name: "Anything At All"})
	if d.Elevates() {
		t.Fatal("the policy default granted administrator rights to an unmatched application")
	}
}

// A rule whose action is "default" is a carve-out: it stops the search and
// hands the decision to the policy's fallback. The DEFAULT decided, so nothing
// gated on a rule having decided may fire.
func TestACarveOutRuleDoesNotCountAsARuleDecision(t *testing.T) {
	eff := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionElevate,
		Rules: []EffectiveRule{{
			PolicyName: "Carve out", Mode: ModeEnforce,
			Rule: Rule{
				Name: "exempt", Enabled: true, Action: ActionDefault,
				Match: MatchCriteria{AppName: StringMatch{Op: OpEquals, Values: []string{"Thing"}}},
			},
		}},
	}

	d := eff.Evaluate(Program{Name: "Thing"})
	if d.FromRule {
		t.Error("a carve-out rule claimed the decision was its own")
	}
	if d.Elevates() {
		t.Fatal("a carve-out rule routed around the default-cannot-elevate guard")
	}
}

// Refusing to run something is a recoverable mistake. Running it as
// administrator is not. Where both could apply, the block has to win — and
// with first-match-wins that means the ORDER an operator sees must be the
// order that decides, with no special case quietly reordering it.
func TestAnEarlierBlockBeatsALaterElevate(t *testing.T) {
	eff := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{
			{PolicyName: "Deny", Mode: ModeEnforce, Rule: Rule{
				Name: "no", Enabled: true, Action: ActionBlock,
				Match: MatchCriteria{AppName: StringMatch{Op: OpEquals, Values: []string{"Tool"}}},
			}},
			{PolicyName: "Allow", Mode: ModeEnforce, Rule: Rule{
				Name: "yes", Enabled: true, Action: ActionElevate,
				Match: MatchCriteria{AppName: StringMatch{Op: OpEquals, Values: []string{"Tool"}}},
			}},
		},
	}

	d := eff.Evaluate(Program{Name: "Tool"})
	if d.Action != ActionBlock || d.Elevates() {
		t.Fatalf("the elevate rule won over an earlier block: %+v", d)
	}
}

// Audit mode must not grant rights, exactly as it does not take them away.
func TestAuditModeGrantsNothing(t *testing.T) {
	eff := elevateRule("Installer")
	eff.Mode = ModeAudit

	d := eff.Evaluate(Program{Name: "Installer"})
	if d.Enforced {
		t.Error("audit mode reported the decision as enforced")
	}
	// The ACTION is still reported — that is the point of audit — but the
	// caller must not act, and Enforced is how it knows.
	if d.Action != ActionElevate {
		t.Errorf("audit mode should still report what it would do, got %q", d.Action)
	}
}
