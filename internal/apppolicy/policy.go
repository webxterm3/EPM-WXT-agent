// Package apppolicy holds the application-control policy a machine has been
// given, and decides what it says about a program that is about to run.
//
// The decision logic mirrors the backend's internal/policy package, and
// deliberately so: the portal's "Project impact" screen and the endpoint must
// agree about what a rule does, or the simulation an operator approved is not
// the thing that ships.
//
// Nothing here starts a process, kills one, or touches the filesystem. It is a
// pure decision over values, so that the rule that matters most — empty
// criteria match NOTHING — can be tested exhaustively.
package apppolicy

import (
	"path/filepath"
	"strings"
	"time"
)

// Modes. Audit records what would have happened; enforce acts.
const (
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

// Actions.
const (
	ActionAllow   = "allow"
	ActionBlock   = "block"
	ActionElevate = "elevate"
	ActionDefault = "default"
)

// Match operators.
const (
	OpEquals   = "equals"
	OpContains = "contains"
	OpPrefix   = "prefix"
	OpSuffix   = "suffix"
	OpWildcard = "wildcard"
)

// StringMatch is one field's comparison. Values are alternatives (OR).
type StringMatch struct {
	Op            string   `json:"op"`
	Values        []string `json:"values"`
	CaseSensitive bool     `json:"case_sensitive"`
}

// Empty reports whether this field constrains anything.
func (m StringMatch) Empty() bool {
	for _, v := range m.Values {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// MatchCriteria selects programs. Populated fields are ANDed.
type MatchCriteria struct {
	AppName   StringMatch `json:"app_name"`
	Publisher StringMatch `json:"publisher"`
	FilePath  StringMatch `json:"file_path"`
	BundleID  StringMatch `json:"bundle_id"`
	SHA256    []string    `json:"sha256,omitempty"`
}

// Empty reports whether every field is unset.
func (c MatchCriteria) Empty() bool {
	return c.AppName.Empty() && c.Publisher.Empty() &&
		c.FilePath.Empty() && c.BundleID.Empty() && len(c.SHA256) == 0
}

// Rule is one ordered decision.
type Rule struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Enabled bool          `json:"enabled"`
	Action  string        `json:"action"`
	Match   MatchCriteria `json:"match"`
}

// EffectiveRule is a rule plus where it came from, so a decision can say which
// policy produced it rather than only what it did.
type EffectiveRule struct {
	Rule       Rule   `json:"rule"`
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Scope      string `json:"scope"`
	Mode       string `json:"mode"`

	// RemoveBlocked carries the owning policy's choice about how hard a block
	// should bite: stop it launching, or move it off the machine altogether.
	//
	// It travels on the RULE rather than on the policy as a whole because
	// rules from several policies are flattened into one list here, and by
	// the time a decision is made there is no policy left to ask.
	RemoveBlocked bool `json:"remove_blocked,omitempty"`
}

// Effective is the whole policy for this machine, in evaluation order. It is
// exactly what the backend serialises.
type Effective struct {
	AgentID       string          `json:"agent_id"`
	TenantID      string          `json:"tenant_id"`
	Mode          string          `json:"mode"`
	DefaultAction string          `json:"default_action"`
	Rules         []EffectiveRule `json:"rules"`

	// ApprovedInstalls are one-off exceptions an administrator granted,
	// usually in answer to a request raised from this machine.
	//
	// A NEW field, which is the direction a version mismatch has to fail in:
	// an agent that predates it ignores it and keeps blocking. Attaching the
	// same meaning to an existing field would have an old agent half-
	// understand it and allow something indefinitely.
	ApprovedInstalls []ApprovedInstall `json:"approved_installs,omitempty"`
}

// ApprovedInstall is permission for one application, until one moment.
type ApprovedInstall struct {
	Application string    `json:"application"`
	BundleID    string    `json:"bundle_id,omitempty"`
	Publisher   string    `json:"publisher,omitempty"`
	Until       time.Time `json:"until"`

	// Operation is what was approved: install, update or remove.
	//
	// Empty means install, so an approval stored or sent before this field
	// existed keeps exactly the meaning it was granted with — and an agent
	// that predates the field ignores it and reads every approval as the
	// install approval it already understood, which is the direction a
	// version mismatch has to fail in.
	Operation string `json:"operation,omitempty"`

	// Spent marks an approval that has already been used — the software was
	// installed and this machine said so.
	//
	// It stops permitting a NEW install: somebody who uninstalls the
	// software and wants it back asks again, because the approver agreed to
	// one install and not to a standing permission for the rest of the day.
	// It goes on exempting what is already on the machine from enforcement,
	// which is a different question — the software is there because it was
	// approved, and withdrawing that would have the agent quarantine the
	// very thing it had just been told to install.
	//
	// Absent on an older backend, which reads as "not spent" — the
	// behaviour this field changed, so nothing is surprised by its absence.
	Spent bool `json:"spent,omitempty"`
}

// Operations an approval can carry.
const (
	OpInstall = "install"
	OpUpdate  = "update"
	OpRemove  = "remove"
)

// permits reports whether this approval covers one operation.
//
// Installing covers updating and removing: somebody allowed to put an
// application on this machine is allowed to replace it with a newer one and
// to take it off again, and making them raise a second request to undo the
// first would be a worse answer than either. Removing covers only removing —
// permission to take something off is not permission to put something on.
func (a ApprovedInstall) permits(op string) bool {
	switch a.Operation {
	case "", OpInstall:
		return true
	case OpUpdate:
		return op == OpUpdate || op == OpRemove
	case OpRemove:
		return op == OpRemove
	default:
		// An operation this build does not know about grants nothing.
		// Refusing something unrecognised costs a password; honouring it
		// costs whatever the newer side meant by it.
		return false
	}
}

// InstallApproved reports whether a live exception covers this application.
//
// Compared on the name the endpoint reported when it was refused, which is
// what the approver saw and decided about. Where the approval records a
// bundle id or a publisher, those must match too — an exception that matched
// on name alone could be claimed by anything named the same, which is the
// whole trick this feature has to be proof against.
// Enforcing reports whether this policy may act on a machine.
//
// Audit mode means watch and report; it does not mean act quietly. The
// install path read nothing about mode at all, so a policy saved in audit —
// with the tenant's enforcement switch off — still ejected disk images out
// from under people and still handed out permission to remove applications.
// The editor says, in those words, "Matches are recorded and projected.
// Nothing on any machine changes."
//
// nil is not enforcing: a machine that has never been told anything has not
// been told to act.
func (e *Effective) Enforcing() bool {
	return e != nil && e.Mode == ModeEnforce
}

// HasSpentApproval reports whether an approval for this application exists
// but has already been used.
//
// Asked only so a refusal can explain itself: from the outside, software
// refused because its approval was spent looks exactly like software nobody
// ever approved, and those are the two cases somebody most needs to tell
// apart.
func (e *Effective) HasSpentApproval(name string, now time.Time) bool {
	if e == nil {
		return false
	}
	for _, a := range e.ApprovedInstalls {
		if a.Spent && a.Until.After(now) && strings.EqualFold(a.Application, name) {
			return true
		}
	}
	return false
}

// Exempt reports whether a live approval covers this program.
//
// The ONE place the question is asked, because it is asked from three:
// deciding about a mounted image, deciding what to lock or quarantine, and
// deciding what to stop when it launches. Those drifted — only the first
// consulted approvals at all, so an administrator would approve a request,
// the agent would install the software, and the enforcement pass seconds
// later would quarantine it straight back off the machine, or let it sit on
// disk and kill it every time somebody opened it. From the portal it looked
// applied; from the Mac it looked like nothing had happened.
func (e *Effective) Exempt(p Program, now time.Time) bool {
	if e == nil {
		return false
	}
	// A RULE that blocks is not something an approval may set aside.
	//
	// The same precedence the install decision uses, and it has to be the
	// same here or the two halves of the agent disagree about the same
	// application: the mount refuses it, and the enforcement pass leaves it
	// alone because an approval exists — which is an administrator writing a
	// block rule and watching the software stay exactly where it was.
	if d := e.Evaluate(p); d.Action == ActionBlock && d.FromRule {
		return false
	}
	// A spent approval still covers what it put there.
	//
	// Enforcement is asking whether this may STAY, not whether it may be
	// installed. Refusing a spent one here would have the agent quarantine
	// software the moment it finished installing it, on the strength of the
	// endpoint reporting success.
	return e.approvalCovers(p.Name, p.BundleID, p.Publisher, now, true)
}

// RemovalApproved reports whether a live approval names this application, by
// NAME alone.
//
// Deliberately separate from InstallApproved, and deliberately weaker.
//
// InstallApproved refuses to match when the caller cannot supply the bundle
// identifier and publisher the approval was granted against — that is what
// stops an unsigned lookalike in a disk image inheriting somebody else's
// permission, and it must stay that way. Calling it with empty strings looks
// like a lookup and silently never matches, because an endpoint-raised
// approval always carries both.
//
// Removal is a different question. The bundle is already in /Applications,
// so it was put there by something that passed the install check, and
// renaming it to impersonate another application needs delete_child on
// /Applications, which nobody is ever granted. The name is therefore enough
// here, and reading each installed bundle's signature on every scan would be
// a codesign call per application every few seconds.
func (e *Effective) RemovalApproved(name string, now time.Time) bool {
	for _, a := range e.ApprovedInstalls {
		if a.Until.After(now) && strings.EqualFold(a.Application, name) && a.permits(OpRemove) {
			return true
		}
	}
	return false
}

func (e *Effective) InstallApproved(name, bundleID, publisher string, now time.Time) bool {
	return e.approvalCovers(name, bundleID, publisher, now, false)
}

// approvalCovers is the shared matcher. allowSpent is what separates the two
// questions an approval answers: may this be installed (no), and may what is
// already installed stay (yes).
func (e *Effective) approvalCovers(name, bundleID, publisher string, now time.Time, allowSpent bool) bool {
	for _, a := range e.ApprovedInstalls {
		if !a.Until.After(now) {
			continue
		}
		if !strings.EqualFold(a.Application, name) {
			continue
		}
		// Both sides must HAVE an identifier before it can disagree.
		//
		// This used to key on the approval's value alone, which failed in
		// one direction only: an approval recording a bundle id, matched
		// against a bundle whose Info.plist could not be read, compared the
		// id against "" and never matched. The person had asked, been
		// approved, and was still refused — with nothing anywhere saying
		// why. When either side is missing, the name and the publisher are
		// what is left to go on, and the publisher is the part that carries
		// the weight.
		if a.BundleID != "" && bundleID != "" && !strings.EqualFold(a.BundleID, bundleID) {
			continue
		}
		// EqualFold, like the two comparisons above it. A signing authority
		// is read back from codesign and matched against a string stored
		// when the request was raised; a difference in case between the two
		// is not somebody else's certificate.
		if a.Publisher != "" && !strings.EqualFold(a.Publisher, publisher) {
			continue
		}
		if !a.permits(OpInstall) {
			continue
		}
		// Already used. Installing again is a new ask — but what is
		// already on the machine is not asked about again.
		if a.Spent && !allowSpent {
			continue
		}
		return true
	}
	return false
}

// Program is a candidate to decide about.
type Program struct {
	Name      string
	Publisher string
	Path      string
	BundleID  string
	SHA256    string
}

// Decision is the answer for one program.
type Decision struct {
	Action string
	// Rule is the rule that decided; empty when the default applied.
	Rule       string
	PolicyName string
	// Enforced is true only when the policy is in enforce mode. In audit mode
	// the action is still reported — that is the point of audit — but nothing
	// acts on it.
	Enforced bool

	// Remove asks for a blocked application to be moved off the machine
	// rather than merely prevented from launching.
	//
	// Only ever true alongside Action == ActionBlock. It is false whenever the
	// policy default decided rather than a rule, because a catch-all that
	// swept somebody's whole Applications folder into quarantine is not
	// something a default should be able to express.
	Remove bool

	// FromRule is true when a rule decided, false when the policy's default
	// action did.
	//
	// It exists because the two are not interchangeable for anything that
	// GIVES rights away. A default of allow is a reasonable thing to fall back
	// on; a default that elevates would mean every unmatched application runs
	// as administrator. Callers that hand out privilege check this.
	FromRule bool
}

// Elevates reports whether this decision grants administrator rights.
//
// A method rather than a comparison at each call site, because the condition
// is not just "the action is elevate": it must also have come from a rule. The
// backend already refuses to store a default action of elevate, and this is
// the second lock on the same door — the one that holds even if a policy
// arrives from an older backend, a hand-edited document, or a future bug.
func (d Decision) Elevates() bool {
	return d.Action == ActionElevate && d.FromRule
}

// Evaluate returns what the policy says about one program.
//
// First matching rule wins: the order the operator sees in the editor, and the
// order the simulation used.
func (e *Effective) Evaluate(p Program) Decision {
	enforced := e.Mode == ModeEnforce

	for i, er := range e.Rules {
		if !er.Rule.Enabled || !matches(er.Rule.Match, p) {
			continue
		}
		action := er.Rule.Action
		fromRule := true
		if action == ActionDefault {
			// The rule is a carve-out: it says "stop looking, use the
			// default". The DEFAULT decided, not the rule, so anything gated
			// on a rule having decided must not fire.
			action = e.defaultAction()
			fromRule = false
		}

		// One exception to first-match-wins, and only one: a block anywhere
		// below beats an elevate.
		//
		// elevate.go states this as a safety rule — "a block always beats an
		// elevate for the same application; refusing to run something is a
		// safe mistake, running it as administrator is not" — and until now
		// nothing implemented it. Ordering an elevate rule above a block rule
		// did not merely elevate instead of blocking: no platform implements
		// elevation, so the elevate did nothing, the block never ran, and the
		// application the operator had forbidden simply started. One rule
		// silently disabling another is the worst shape a policy engine has,
		// because the editor shows both as enabled.
		//
		// Scoped to elevate deliberately. An allow above a block is an
		// operator saying "this one is fine", which is what rule order is
		// for, and overriding that would make the editor's order a lie in the
		// other direction.
		if action == ActionElevate && fromRule {
			if blocked, ok := e.laterBlock(p, i); ok {
				return blocked
			}
		}

		return Decision{
			Action: action, Rule: er.Rule.Name,
			PolicyName: er.PolicyName, Enforced: enforced,
			// Removal is a property of the rule that matched, and only
			// meaningful for a block.
			Remove:   er.RemoveBlocked && action == ActionBlock && fromRule,
			FromRule: fromRule,
		}
	}

	return Decision{Action: e.defaultAction(), Enforced: enforced}
}

// laterBlock looks past an elevate rule for a block rule that also matches.
//
// Only called for an elevate, so the ordinary path stays a single pass and
// first-match-wins everywhere else.
// Indexed rather than compared by value: EffectiveRule carries match criteria
// holding slices, so == does not compile on it and comparing by name would
// pick the wrong rule whenever two share one — which preparePolicy permits.
func (e *Effective) laterBlock(p Program, from int) (Decision, bool) {
	// Strictly after the rule that matched. A block ABOVE the elevate is left
	// alone: it would already have won on its own.
	for _, er := range e.Rules[from+1:] {
		if !er.Rule.Enabled || er.Rule.Action != ActionBlock || !matches(er.Rule.Match, p) {
			continue
		}
		return Decision{
			Action: ActionBlock, Rule: er.Rule.Name,
			PolicyName: er.PolicyName, Enforced: e.Mode == ModeEnforce,
			Remove:   er.RemoveBlocked,
			FromRule: true,
		}, true
	}
	return Decision{}, false
}

func (e *Effective) defaultAction() string {
	if e.DefaultAction == "" {
		// Allow, never block. A policy that arrived truncated, or from a
		// backend older than this agent, must not brick the machine.
		return ActionAllow
	}
	return e.DefaultAction
}

// matches reports whether a program satisfies a rule's criteria.
//
// Empty criteria match NOTHING. This is the most important line here: a rule
// saved from a half-filled form would otherwise match every program on the
// machine, and if its action were block, that is this endpoint refusing to run
// anything at all.
func matches(c MatchCriteria, p Program) bool {
	if c.Empty() {
		return false
	}
	if !matchField(c.AppName, p.Name) {
		return false
	}
	if !matchField(c.Publisher, p.Publisher) {
		return false
	}
	if !matchField(c.BundleID, p.BundleID) {
		return false
	}
	if !c.FilePath.Empty() && !matchPath(c.FilePath, p.Path) {
		return false
	}
	if len(c.SHA256) > 0 && !matchHash(c.SHA256, p.SHA256) {
		return false
	}
	return true
}

// matchField reports whether one value satisfies one field's criteria.
//
// An unset field constrains nothing and therefore matches — that is what makes
// "publisher = Acme" a rule about publishers rather than one that also
// requires an empty name.
func matchField(m StringMatch, value string) bool {
	if m.Empty() {
		return true
	}

	subject := value
	if !m.CaseSensitive {
		subject = strings.ToLower(subject)
	}

	for _, raw := range m.Values {
		want := strings.TrimSpace(raw)
		if want == "" {
			continue
		}
		if !m.CaseSensitive {
			want = strings.ToLower(want)
		}
		if matchOne(m.Op, subject, want) {
			return true
		}
	}
	return false
}

// matchOne applies a single operator.
//
// An unrecognised operator is treated as equals rather than as "matches
// everything": a typo in a stored rule must not quietly widen it.
func matchOne(op, subject, want string) bool {
	switch op {
	case OpContains:
		return strings.Contains(subject, want)
	case OpPrefix:
		return strings.HasPrefix(subject, want)
	case OpSuffix:
		return strings.HasSuffix(subject, want)
	case OpWildcard:
		ok, err := filepath.Match(want, subject)
		return err == nil && ok
	default:
		return subject == want
	}
}

// matchPath compares paths with separators normalised: a Windows path arrives
// with either separator and in any case, and a rule written with one spelling
// would silently miss the other.
func matchPath(m StringMatch, path string) bool {
	normalised := StringMatch{Op: m.Op, CaseSensitive: m.CaseSensitive}
	for _, v := range m.Values {
		normalised.Values = append(normalised.Values, normalisePath(v))
	}
	return matchField(normalised, normalisePath(path))
}

func normalisePath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// matchHash compares a program's hash against a rule's list.
//
// A program with no known hash never matches a hash rule: guessing would be a
// decision made on no evidence, and in the block direction that is somebody's
// program refused for nothing.
func matchHash(wanted []string, actual string) bool {
	if actual == "" {
		return false
	}
	actual = strings.ToLower(strings.TrimSpace(actual))
	for _, w := range wanted {
		if strings.ToLower(strings.TrimSpace(w)) == actual {
			return true
		}
	}
	return false
}
