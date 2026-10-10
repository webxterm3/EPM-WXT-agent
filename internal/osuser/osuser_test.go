package osuser

import (
	"strings"
	"testing"
)

func has(t *testing.T, got []string, want string) {
	t.Helper()
	for _, g := range got {
		if g == want {
			return
		}
	}
	t.Errorf("%q is never tried; candidates = %v", want, got)
}

// The failure this package exists for: a laptop joined to Entra ID stores the
// account as AzureAD\name while everything the operator sees says "ITSupport".
func TestEntraJoinedNameIsTried(t *testing.T) {
	got := Candidates("ITSupport", "DESKTOP-5KQ", "")
	has(t, got, `AzureAD\ITSupport`)
	has(t, got, `DESKTOP-5KQ\ITSupport`)
}

// The bare name is still tried first. On a plain local account it is the
// answer, and spending two failed lookups to get there would be silly.
func TestBareNameIsTriedFirst(t *testing.T) {
	got := Candidates("ITSupport", "DESKTOP-5KQ", "CORP")
	if len(got) == 0 || got[0] != "ITSupport" {
		t.Fatalf("candidates = %v, want the configured name first", got)
	}
}

// Somebody who configured DOMAIN\user knows something we do not, so that form
// is tried exactly as given before anything is inferred from it.
func TestQualifiedNameIsTriedAsGivenFirst(t *testing.T) {
	got := Candidates(`CORP\priya`, "LAPTOP-7", "CORP")
	if got[0] != `CORP\priya` {
		t.Fatalf("candidates = %v, want the configured name first", got)
	}
	// ...and the bare name too, for a machine that has since left the domain.
	has(t, got, "priya")
}

func TestUserDomainIsTried(t *testing.T) {
	has(t, Candidates("priya", "LAPTOP-7", "CORP"), `CORP\priya`)
}

// Each failed candidate is a round trip to the account database, and on a
// domain-joined machine that can mean a wire call.
func TestCandidatesAreNotRepeated(t *testing.T) {
	// hostname and USERDOMAIN are the same on a workgroup machine, which is
	// the common case, so this duplicate is the one that actually shows up.
	got := Candidates("ITSupport", "DESKTOP-5KQ", "DESKTOP-5KQ")
	seen := map[string]bool{}
	for _, c := range got {
		if seen[strings.ToLower(c)] {
			t.Errorf("%q is looked up twice; candidates = %v", c, got)
		}
		seen[strings.ToLower(c)] = true
	}
}

func TestNoNameMeansNoLookups(t *testing.T) {
	if got := Candidates("   ", "DESKTOP-5KQ", "CORP"); len(got) != 0 {
		t.Errorf("a blank username produced lookups: %v", got)
	}
}

// A trailing backslash would otherwise generate the candidate `\`, which is
// not a name and costs a lookup to find that out.
func TestTrailingSeparatorDoesNotProduceAnEmptyName(t *testing.T) {
	for _, c := range Candidates(`CORP\`, "LAPTOP-7", "CORP") {
		if c == `\` || strings.HasSuffix(c, `\`) {
			t.Errorf("candidate %q is not a name", c)
		}
	}
}
