package apppolicy

import "testing"

func rule(name, action string, m MatchCriteria) EffectiveRule {
	return EffectiveRule{
		Rule:       Rule{ID: name, Name: name, Enabled: true, Action: action, Match: m},
		PolicyName: "test", Mode: ModeEnforce,
	}
}

func exact(values ...string) StringMatch {
	return StringMatch{Op: OpEquals, Values: values}
}

// The single most important rule in this package. A rule saved from a
// half-filled form must match NOTHING — not everything — or a block rule
// becomes an endpoint that refuses to run any program at all.
func TestEmptyCriteriaMatchNothing(t *testing.T) {
	p := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{rule("empty", ActionBlock, MatchCriteria{})},
	}
	d := p.Evaluate(Program{Name: "Google Chrome", Path: "/Applications/Google Chrome.app"})
	if d.Action != ActionAllow {
		t.Fatalf("an empty rule blocked a program: %+v", d)
	}
}

// Populated fields are ANDed. A bundle id carried onto a Windows program —
// which has none — must not match, or a rule written for a Mac would quietly
// start blocking on Windows.
func TestPopulatedFieldsAreAnded(t *testing.T) {
	p := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{rule("chrome", ActionBlock, MatchCriteria{
			AppName:  exact("Google Chrome"),
			BundleID: exact("com.google.Chrome"),
		})},
	}

	win := p.Evaluate(Program{Name: "Google Chrome", Path: `C:\Program Files\Google\Chrome\chrome.exe`})
	if win.Action != ActionAllow {
		t.Errorf("a bundle-id rule matched a Windows program with no bundle id: %+v", win)
	}

	mac := p.Evaluate(Program{Name: "Google Chrome", BundleID: "com.google.Chrome"})
	if mac.Action != ActionBlock {
		t.Errorf("the rule did not match the program it was written for: %+v", mac)
	}
}

// The order in the editor is the order on the endpoint. An exception placed
// above a broad rule has to win, or every carve-out an operator writes is
// silently ineffective.
func TestFirstMatchingRuleWins(t *testing.T) {
	p := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{
			rule("allow finance build", ActionAllow, MatchCriteria{FilePath: StringMatch{Op: OpContains, Values: []string{"/finance/"}}}),
			rule("block chrome", ActionBlock, MatchCriteria{AppName: exact("Google Chrome")}),
		},
	}
	d := p.Evaluate(Program{Name: "Google Chrome", Path: "/opt/finance/chrome"})
	if d.Action != ActionAllow || d.Rule != "allow finance build" {
		t.Errorf("the exception above the broad rule did not win: %+v", d)
	}
}

// Audit mode still reports what WOULD happen. Flattening the action to allow
// would make the audit trail useless, and flipping Enforced on would make
// audit mode block.
func TestAuditModeDecidesButDoesNotEnforce(t *testing.T) {
	p := &Effective{
		Mode: ModeAudit, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{rule("block chrome", ActionBlock, MatchCriteria{AppName: exact("Google Chrome")})},
	}
	d := p.Evaluate(Program{Name: "Google Chrome"})
	if d.Action != ActionBlock {
		t.Errorf("audit mode hid the decision: %+v", d)
	}
	if d.Enforced {
		t.Error("audit mode reported the decision as enforced")
	}
}

// A policy that arrives truncated, or from a backend older than this agent,
// must not brick the machine it lands on.
func TestAMissingDefaultActionAllows(t *testing.T) {
	p := &Effective{Mode: ModeEnforce}
	if d := p.Evaluate(Program{Name: "anything"}); d.Action != ActionAllow {
		t.Errorf("an empty policy produced %q, want allow", d.Action)
	}
}

// Publisher rules are how "block everything from this vendor" is written, and
// are the case the user asked for by name.
func TestPublisherRuleMatchesEveryProgramFromThatPublisher(t *testing.T) {
	p := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{rule("block vendor", ActionBlock, MatchCriteria{Publisher: exact("Valve Corporation")})},
	}
	for _, name := range []string{"Steam", "Steam Helper", "SteamVR"} {
		if d := p.Evaluate(Program{Name: name, Publisher: "Valve Corporation"}); d.Action != ActionBlock {
			t.Errorf("%s from a blocked publisher was %q", name, d.Action)
		}
	}
	if d := p.Evaluate(Program{Name: "Steam", Publisher: "Someone Else"}); d.Action != ActionAllow {
		t.Error("a same-named program from a different publisher was blocked")
	}
}

// Windows paths arrive with either separator and in any case.
func TestPathMatchingIgnoresSeparatorAndCase(t *testing.T) {
	p := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{rule("block dir", ActionBlock, MatchCriteria{
			FilePath: StringMatch{Op: OpContains, Values: []string{`C:\Program Files\Steam`}},
		})},
	}
	d := p.Evaluate(Program{Name: "steam.exe", Path: "c:/program files/steam/steam.exe"})
	if d.Action != ActionBlock {
		t.Errorf("a path rule missed the other spelling of the same location: %+v", d)
	}
}

// A disabled rule contributes nothing — it is kept so it can be switched back
// on, not so it can keep acting.
func TestDisabledRulesAreSkipped(t *testing.T) {
	r := rule("block chrome", ActionBlock, MatchCriteria{AppName: exact("Google Chrome")})
	r.Rule.Enabled = false
	p := &Effective{Mode: ModeEnforce, DefaultAction: ActionAllow, Rules: []EffectiveRule{r}}
	if d := p.Evaluate(Program{Name: "Google Chrome"}); d.Action != ActionAllow {
		t.Errorf("a disabled rule still decided: %+v", d)
	}
}

// A program with no hash must never match a hash rule: in the block direction
// that is somebody's program refused on no evidence.
func TestHashRulesNeverMatchAnUnknownHash(t *testing.T) {
	p := &Effective{
		Mode: ModeEnforce, DefaultAction: ActionAllow,
		Rules: []EffectiveRule{rule("block build", ActionBlock, MatchCriteria{SHA256: []string{"abc123"}})},
	}
	if d := p.Evaluate(Program{Name: "thing"}); d.Action != ActionAllow {
		t.Errorf("a hash rule matched a program with no hash: %+v", d)
	}
}
