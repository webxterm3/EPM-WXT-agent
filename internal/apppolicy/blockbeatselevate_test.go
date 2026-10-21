package apppolicy

import "testing"

// Named apart from elevate_test.go's elevateRule, which builds a whole
// Effective; these build one rule so ORDER can be expressed.
func mayElevate(name string, match MatchCriteria) EffectiveRule {
	return EffectiveRule{Rule: Rule{Name: name, Enabled: true, Action: ActionElevate, Match: match}}
}

func mustBlock(name string, match MatchCriteria) EffectiveRule {
	return EffectiveRule{Rule: Rule{Name: name, Enabled: true, Action: ActionBlock, Match: match}}
}

func named(v string) MatchCriteria {
	return MatchCriteria{AppName: StringMatch{Op: OpEquals, Values: []string{v}}}
}

// elevate.go states this as a safety rule: "a block always beats an elevate
// for the same application. Refusing to run something is a safe mistake;
// running it as administrator is not." Nothing implemented it.
//
// The consequence was worse than the wrong privilege. No platform implements
// elevation, so an elevate rule ordered above a block did not elevate — it
// returned first, the block below never ran, and the application the operator
// had forbidden simply started. One enabled rule silently cancelling another,
// with the editor showing both as active.
func TestABlockBelowAnElevateStillBlocks(t *testing.T) {
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionAllow,
		Rules: []EffectiveRule{
			mayElevate("devs may elevate Docker", named("Docker Desktop")),
			mustBlock("Docker is not approved", named("Docker Desktop")),
		},
	}

	d := eff.Evaluate(Program{Name: "Docker Desktop"})

	if d.Action == ActionElevate {
		t.Fatal("the elevate won, so nothing elevates it (no platform can) and the " +
			"block below never runs — the forbidden application simply starts")
	}
	if d.Action != ActionBlock {
		t.Fatalf("decided %q, want %q", d.Action, ActionBlock)
	}
	if d.Rule != "Docker is not approved" {
		t.Errorf("attributed to %q — the event and the portal would name the wrong rule", d.Rule)
	}
}

// Order still means what the editor says it means for everything else. An
// allow above a block is an operator writing a carve-out, and overriding that
// would make rule order a lie in the other direction.
func TestAnAllowAboveABlockStillWins(t *testing.T) {
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionAllow,
		Rules: []EffectiveRule{
			{Rule: Rule{Name: "finance may use it", Enabled: true, Action: ActionAllow, Match: named("Steam")}},
			mustBlock("no games", named("Steam")),
		},
	}
	if d := eff.Evaluate(Program{Name: "Steam"}); d.Action != ActionAllow {
		t.Errorf("decided %q — an explicit allow above a block must still win", d.Action)
	}
}

// A block ABOVE an elevate already won on its own; the scan must not change
// which rule is credited.
func TestABlockAboveAnElevateIsUnchanged(t *testing.T) {
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionAllow,
		Rules: []EffectiveRule{
			mustBlock("blocked first", named("Wireshark")),
			mayElevate("net team may elevate", named("Wireshark")),
		},
	}
	d := eff.Evaluate(Program{Name: "Wireshark"})
	if d.Action != ActionBlock || d.Rule != "blocked first" {
		t.Errorf("decided %q by %q, want block by %q", d.Action, d.Rule, "blocked first")
	}
}

// A block that does not match is not a block. The scan must compare criteria,
// not merely find the next block in the list.
func TestAnUnrelatedBlockDoesNotCancelAnElevate(t *testing.T) {
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionAllow,
		Rules: []EffectiveRule{
			mayElevate("devs may elevate Docker", named("Docker Desktop")),
			mustBlock("no games", named("Steam")),
		},
	}
	if d := eff.Evaluate(Program{Name: "Docker Desktop"}); d.Action != ActionElevate {
		t.Errorf("decided %q — a block for a different application cancelled the elevate", d.Action)
	}
}

// A disabled block is not a block.
func TestADisabledBlockDoesNotCancelAnElevate(t *testing.T) {
	disabled := mustBlock("switched off", named("Docker Desktop"))
	disabled.Rule.Enabled = false

	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionAllow,
		Rules:         []EffectiveRule{mayElevate("may elevate", named("Docker Desktop")), disabled},
	}
	if d := eff.Evaluate(Program{Name: "Docker Desktop"}); d.Action != ActionElevate {
		t.Errorf("decided %q — a disabled rule was honoured", d.Action)
	}
}
