package agent

import (
	"strings"
	"testing"
)

// The menu bar offers a route, and the agent decides whether to take it.
// Those are two different files, and they drifted.
//
// The menu row was made clickable for no-policy software — the ordinary
// answer in a default-deny estate, where most things have no rule written
// about them — while requestApproval still tested for "blocked" alone and
// returned. Everything else about that path worked: the file was written,
// the agent read it, and the dialog said "has been asked to approve". The
// request simply stopped there, with no log line, because the return came
// before the logging. The only way to find out was that nothing ever
// appeared in the portal and nothing anywhere said why.
//
// There is now one source of truth, Outcome.Requestable(), and these tests
// exist to keep it that way: the moment either side writes down its own
// list of outcomes, the two can disagree again without anything failing.
func TestNeitherSideKeepsItsOwnListOfWhatCanBeAskedAbout(t *testing.T) {
	for _, place := range []struct {
		file, fn string
	}{
		{"cmd/menubar/software.go", "func rowFor("},
		{"internal/agent/pendinginstall.go", "func (a *Agent) requestApproval"},
	} {
		body := codeOnly(sourceBetween(t, readSource(t, place.file), place.fn, "\nfunc "))

		if !strings.Contains(body, "Requestable()") {
			t.Errorf("%s no longer asks Outcome.Requestable()", place.file)
		}
		for _, named := range []string{"OutcomeBlocked", "OutcomeNoPolicy", `"blocked"`, `"no-policy"`} {
			if strings.Contains(body, named) {
				t.Errorf("%s names %s itself — that is the second list that caused "+
					"somebody to be told their request had been sent when it had not",
					place.file, named)
			}
		}
	}
}

// And the guard has to ask the shared question rather than name outcomes of
// its own, or the two can disagree again without anything failing.
func TestTheAgentAsksTheSharedQuestion(t *testing.T) {
	src := readSource(t, "internal/agent/pendinginstall.go")
	guard := sourceBetween(t, src, "func (a *Agent) requestApproval", "\nfunc ")

	if !strings.Contains(guard, "Requestable()") {
		t.Error("requestApproval no longer uses Outcome.Requestable(); if it names " +
			"outcomes itself it will drift from the menu again")
	}
	for _, named := range []string{"OutcomeBlocked", "OutcomeNoPolicy"} {
		if strings.Contains(guard, named) {
			t.Errorf("requestApproval names %s directly — that is the second list "+
				"that caused this bug", named)
		}
	}
}

// codeOnly drops line comments, so prose explaining the bug — which
// necessarily names the outcomes — is not mistaken for the bug.
func codeOnly(src string) string {
	var kept []string
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func sourceBetween(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("%s is gone", start)
	}
	rest := src[i+len(start):]
	if j := strings.Index(rest, end); j >= 0 {
		return rest[:j]
	}
	return rest
}

// The AUTOMATIC ask must go through the same gate as the clicked one.
//
// rescanVolumes raises a request the moment an image is refused, without
// waiting for anybody to press anything. Queuing every non-installable
// outcome would put unverified bundles back on the approval queue through a
// door the clicked path had already closed — and no approval can redeem
// them, because the signature is what is missing.
func TestTheAutomaticAskUsesTheSameGate(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) rescanVolumes", "\nfunc "))

	if !strings.Contains(body, "d.Outcome.Requestable()") {
		t.Error("the automatic ask does not test Requestable(), so an unverified " +
			"bundle raises a request no approval can satisfy")
	}
}
