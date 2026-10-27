package appcontrol

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every place that decides whether to act against an application must ask
// about approvals, and must ask the SAME question.
//
// They drifted once, in the way that costs the most: only the mount decision
// consulted approvals. So an administrator approved a request, the agent
// installed the software, and the enforcement pass seconds later quarantined
// it straight back off the machine — or left it on disk and killed it every
// time somebody opened it. Nothing failed anywhere. From the portal the
// approval looked applied, and from the Mac it looked like nobody had
// answered.
func TestEveryEnforcementPathConsultsApprovals(t *testing.T) {
	src := readSource(t, "internal/appcontrol/appcontrol.go")

	for _, fn := range []string{
		"func (e *Enforcer) decideLocks",
		"func (e *Enforcer) sweepProcesses",
	} {
		body := functionBody(t, src, fn)
		if !strings.Contains(body, "pol.Exempt(") {
			t.Errorf("%s does not consult approvals, so it will act against "+
				"software an approver has allowed", fn)
		}
	}

	// And the carried-forward quarantine loop, which is a separate pass over
	// what is ALREADY held — an approval has to release those too, or
	// approving something that was quarantined leaves it quarantined.
	held := functionBody(t, src, "func (e *Enforcer) decideLocks")
	if i := strings.Index(held, "e.state.all()"); i < 0 {
		t.Fatal("the carried-forward quarantine loop is gone")
	} else if !strings.Contains(held[i:], "pol.Exempt(") {
		t.Error("an application already in quarantine is never released by an " +
			"approval, so approving it changes nothing")
	}
}

// One question, asked from one place.
func TestTheExemptionIsAskedThroughTheSharedHelper(t *testing.T) {
	src := readSource(t, "internal/appcontrol/appcontrol.go")
	if strings.Contains(stripComments(src), "InstallApproved(") {
		t.Error("appcontrol calls InstallApproved directly instead of Exempt — " +
			"that is the second copy of the question that caused the drift")
	}
}

func readSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatalf("could not read %s: %v", rel, err)
	}
	return string(b)
}

// functionBody returns one function's source, up to the next top-level func.
func functionBody(t *testing.T, src, start string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("%s is gone", start)
	}
	rest := src[i+len(start):]
	if j := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest); j != nil {
		return rest[:j[0]]
	}
	return rest
}

func stripComments(src string) string {
	var kept []string
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
