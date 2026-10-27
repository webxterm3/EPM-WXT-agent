package apppolicy

import (
	"testing"
	"time"
)

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

// Removal is asked by name, and installing is not.
//
// InstallApproved refuses to match when the caller cannot supply the bundle
// identifier and publisher the approval was granted against — which is what
// stops an unsigned lookalike inheriting somebody else's permission. Calling
// it with empty strings therefore LOOKS like a lookup and silently never
// matches, because an endpoint-raised approval always carries both. That is
// the shape of mistake this pair of tests exists to prevent.
func TestAnEndpointRaisedApprovalCoversRemovingTheApplication(t *testing.T) {
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Visual Studio Code",
		Publisher:   "Developer ID Application: Microsoft Corporation (UBF8T346G9)",
		BundleID:    "com.microsoft.VSCode",
		Until:       time.Now().Add(time.Hour),
	}}}

	if !eff.RemovalApproved("Visual Studio Code", time.Now()) {
		t.Error("an approved application cannot be removed, so somebody has to " +
			"raise a second request to undo the first")
	}
	// The reason the separate method exists.
	if eff.InstallApproved("Visual Studio Code", "", "", time.Now()) {
		t.Error("InstallApproved matched without the identity it was granted " +
			"against — that is the guard against a lookalike, and it must hold")
	}
}

func TestAnExpiredApprovalDoesNotCoverRemoval(t *testing.T) {
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Visual Studio Code",
		Until:       time.Now().Add(-time.Minute),
	}}}
	if eff.RemovalApproved("Visual Studio Code", time.Now()) {
		t.Error("an approval that ran out still allows the application to be removed")
	}
}

// An approval that records a bundle identifier must still apply to the thing
// it was granted for when that identifier cannot be read back.
//
// Info.plist reads fail — a damaged bundle, a PlistBuddy that returned
// nothing. The guard used to key on the approval's value alone, so it
// compared a real identifier against "" and never matched: the person had
// asked, been approved, and was still refused, with nothing saying why.
func TestAnApprovalStillAppliesWhenTheBundleIDCannotBeRead(t *testing.T) {
	const pub = "Developer ID Application: Microsoft Corporation (UBF8T346G9)"
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Visual Studio Code",
		BundleID:    "com.microsoft.VSCode",
		Publisher:   pub,
		Until:       time.Now().Add(time.Hour),
	}}}

	if !eff.InstallApproved("Visual Studio Code", "", pub, time.Now()) {
		t.Error("an approved application was refused because its bundle " +
			"identifier could not be read back")
	}
}

// But two identifiers that are both present and differ is a different
// application wearing the same name.
func TestADifferentBundleIDStillCannotClaimTheApproval(t *testing.T) {
	const pub = "Developer ID Application: Microsoft Corporation (UBF8T346G9)"
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Visual Studio Code",
		BundleID:    "com.microsoft.VSCode",
		Publisher:   pub,
		Until:       time.Now().Add(time.Hour),
	}}}

	if eff.InstallApproved("Visual Studio Code", "com.impostor.VSCode", pub, time.Now()) {
		t.Error("a bundle declaring a different identifier claimed the approval")
	}
}

// A signing authority read back from codesign and one stored when the
// request was raised can differ in case. That is not somebody else's
// certificate.
func TestThePublisherIsComparedWithoutRegardToCase(t *testing.T) {
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Claude",
		Publisher:   "Developer ID Application: Anthropic (ABC123DEF4)",
		Until:       time.Now().Add(time.Hour),
	}}}

	if !eff.InstallApproved("Claude", "", "developer id application: anthropic (ABC123DEF4)", time.Now()) {
		t.Error("a difference in case was treated as a different publisher")
	}
}

// And a genuinely different publisher still cannot.
func TestAnotherPublisherStillCannotClaimTheApproval(t *testing.T) {
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Claude",
		Publisher:   "Developer ID Application: Anthropic (ABC123DEF4)",
		Until:       time.Now().Add(time.Hour),
	}}}

	if eff.InstallApproved("Claude", "", "Developer ID Application: Somebody Else (ZZZ)", time.Now()) {
		t.Error("software signed by somebody else inherited the approval")
	}
}

// Permission to put an application on this machine is permission to take it
// off again. Making somebody raise a second request to undo the first would
// be a worse answer than either.
func TestAnInstallApprovalAlsoCoversRemoving(t *testing.T) {
	for _, op := range []string{"", OpInstall} {
		eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
			Application: "Docker Desktop", Operation: op,
			Until: time.Now().Add(time.Hour),
		}}}
		if !eff.RemovalApproved("Docker Desktop", time.Now()) {
			t.Errorf("an approval with operation %q does not cover removing it", op)
		}
		if !eff.InstallApproved("Docker Desktop", "", "", time.Now()) {
			t.Errorf("an approval with operation %q does not cover installing it", op)
		}
	}
}

// But permission to take something off is NOT permission to put something
// on. An approver who agreed to an uninstall has agreed to one thing.
func TestARemoveApprovalDoesNotLetAnythingBeInstalled(t *testing.T) {
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Docker Desktop", Operation: OpRemove,
		Until: time.Now().Add(time.Hour),
	}}}

	if eff.InstallApproved("Docker Desktop", "", "", time.Now()) {
		t.Error("an approval to REMOVE an application was read as permission " +
			"to install it")
	}
	if !eff.RemovalApproved("Docker Desktop", time.Now()) {
		t.Error("an approval to remove an application does not let it be removed")
	}
}

// An operation a newer portal invented grants nothing here. Refusing
// something unrecognised costs a password; honouring it costs whatever the
// newer side meant by it.
func TestAnUnknownOperationGrantsNothing(t *testing.T) {
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Docker Desktop", Operation: "reconfigure",
		Until: time.Now().Add(time.Hour),
	}}}

	if eff.InstallApproved("Docker Desktop", "", "", time.Now()) {
		t.Error("an operation this build does not understand was honoured as install")
	}
	if eff.RemovalApproved("Docker Desktop", time.Now()) {
		t.Error("an operation this build does not understand was honoured as remove")
	}
}

// THE structural guarantee that lets a default-deny policy also remove.
//
// A policy whose default is block has its rules as the ALLOW list, so if the
// catch-all could reach removal it would sweep the whole Applications folder
// off the machine. It cannot: Remove is set only on a decision that came
// from a rule.
//
// The backend used to protect against this by forcing the removal switch off
// for any default-deny policy, which also took removal away from the
// explicit block rules in that policy — and without removal a block on macOS
// is an execute-bit change inside the bundle that macOS 14 refuses without
// App Management, so the application stays installed. This test is what
// makes removing that guard safe.
func TestTheCatchAllCanNeverRemoveAnything(t *testing.T) {
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionBlock,
		Rules: []EffectiveRule{{
			Rule: Rule{
				ID: "allow-slack", Name: "Slack is allowed", Enabled: true,
				Action: ActionAllow,
				Match:  MatchCriteria{AppName: StringMatch{Op: "equals", Values: []string{"Slack"}}},
			},
			PolicyName: "deny by default", Mode: ModeEnforce, RemoveBlocked: true,
		}},
	}

	// Something no rule mentions: blocked by the catch-all.
	d := eff.Evaluate(Program{Name: "Some Other App"})
	if d.Action != ActionBlock {
		t.Fatalf("a default-deny policy answered %q", d.Action)
	}
	if d.Remove {
		t.Fatal("the catch-all would sweep every unlisted application off the " +
			"machine — a default-deny policy would empty the Applications folder")
	}
	if d.FromRule {
		t.Error("the catch-all claims to be a rule")
	}
}

// And an explicit block rule in that same policy DOES remove, which is the
// thing the old guard was taking away.
func TestAnExplicitBlockRuleStillRemovesUnderDefaultDeny(t *testing.T) {
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionBlock,
		Rules: []EffectiveRule{{
			Rule: Rule{
				ID: "no-torrents", Name: "No torrent clients", Enabled: true,
				Action: ActionBlock,
				Match:  MatchCriteria{AppName: StringMatch{Op: "equals", Values: []string{"qBittorrent"}}},
			},
			PolicyName: "deny by default", Mode: ModeEnforce, RemoveBlocked: true,
		}},
	}

	d := eff.Evaluate(Program{Name: "qBittorrent"})
	if !d.Remove {
		t.Error("an explicit block rule does not remove the application, so it " +
			"stays in the Applications folder and is merely closed when opened")
	}
}

// The two halves of the agent must agree about the same application.
//
// The mount decision refuses software a rule blocks, whatever approvals
// exist. If the enforcement pass exempted it instead, an administrator would
// write a block rule and watch the application stay exactly where it was —
// refused at the door and untouched on the disk.
func TestAnApprovalDoesNotExemptSoftwareARuleBlocks(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	eff := &Effective{
		Mode: ModeEnforce,
		Rules: []EffectiveRule{{
			Rule: Rule{
				ID: "b1", Name: "No Claude", Enabled: true, Action: ActionBlock,
				Match: MatchCriteria{AppName: StringMatch{Op: "equals", Values: []string{"Claude"}}},
			},
			PolicyName: "test", Mode: ModeEnforce, RemoveBlocked: true,
		}},
		ApprovedInstalls: []ApprovedInstall{
			{Application: "Claude", Publisher: pub, Until: time.Now().Add(time.Hour)},
		},
	}

	if eff.Exempt(Program{Name: "Claude", Publisher: pub}, time.Now()) {
		t.Error("an approval exempted software a rule blocks, so the block " +
			"rule removes nothing and the application stays installed")
	}
}

// And an approval still exempts software no rule blocks — otherwise
// approving anything would stop meaning anything.
func TestAnApprovalStillExemptsSoftwareNoRuleBlocks(t *testing.T) {
	const pub = "Developer ID Application: Anthropic (ABC123DEF4)"
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionBlock,
		ApprovedInstalls: []ApprovedInstall{
			{Application: "Claude", Publisher: pub, Until: time.Now().Add(time.Hour)},
		},
	}

	if !eff.Exempt(Program{Name: "Claude", Publisher: pub}, time.Now()) {
		t.Error("an approved application is still treated as blocked by the " +
			"catch-all, so approving it changed nothing")
	}
}

// An approval is for one install, not for the rest of the day.
//
// Somebody asks for Slack, an approver says yes, it goes on. If they then
// uninstall it and want it back, that is a new ask — the approver agreed to
// an install, not to a standing permission.
func TestAUsedApprovalWillNotInstallTheSoftwareAgain(t *testing.T) {
	const pub = "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)"
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Slack", Publisher: pub, Spent: true,
		Until: time.Now().Add(time.Hour),
	}}}

	if eff.InstallApproved("Slack", "", pub, time.Now()) {
		t.Error("an approval that has already been used installed the software " +
			"a second time, so uninstalling and reinstalling needs nobody's " +
			"permission for the rest of the day")
	}
}

// But it must still exempt what it put there.
//
// Enforcement asks whether the software may STAY, which is a different
// question. Refusing a spent approval there would have the agent quarantine
// software the moment it finished installing it.
func TestAUsedApprovalStillCoversWhatItInstalled(t *testing.T) {
	const pub = "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)"
	eff := &Effective{
		Mode:          ModeEnforce,
		DefaultAction: ActionBlock,
		ApprovedInstalls: []ApprovedInstall{{
			Application: "Slack", Publisher: pub, Spent: true,
			Until: time.Now().Add(time.Hour),
		}},
	}

	if !eff.Exempt(Program{Name: "Slack", Publisher: pub}, time.Now()) {
		t.Error("the agent would quarantine software it had just been told to " +
			"install, because the approval was marked used the moment it " +
			"reported success")
	}
}

// An approval nobody has used yet installs, as before.
func TestAnUnusedApprovalStillInstalls(t *testing.T) {
	const pub = "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)"
	eff := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Slack", Publisher: pub,
		Until: time.Now().Add(time.Hour),
	}}}

	if !eff.InstallApproved("Slack", "", pub, time.Now()) {
		t.Error("an approval nobody has used does not install the software")
	}
}

// A refusal has to be able to explain itself.
//
// From the outside, software refused because its approval was already used
// looks exactly like software nobody ever approved. Those are the two cases
// somebody most needs to tell apart: one means "ask again", the other means
// "you already did, and used it".
func TestAUsedApprovalCanBeToldApartFromNoApproval(t *testing.T) {
	const pub = "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)"
	used := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Slack", Publisher: pub, Spent: true,
		Until: time.Now().Add(time.Hour),
	}}}

	if !used.HasSpentApproval("Slack", time.Now()) {
		t.Error("nothing can tell that the approval was used, so the refusal " +
			"reads the same as never having asked")
	}
	if used.InstallApproved("Slack", "", pub, time.Now()) {
		t.Error("a used approval still installs")
	}

	none := &Effective{}
	if none.HasSpentApproval("Slack", time.Now()) {
		t.Error("a machine with no approvals claims one was used")
	}

	expired := &Effective{ApprovedInstalls: []ApprovedInstall{{
		Application: "Slack", Spent: true, Until: time.Now().Add(-time.Minute),
	}}}
	if expired.HasSpentApproval("Slack", time.Now()) {
		t.Error("an approval that ran out is reported as merely used, which " +
			"points at the wrong fix")
	}
}
