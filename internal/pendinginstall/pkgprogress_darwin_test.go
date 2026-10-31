//go:build darwin

package pendinginstall

import (
	"os/exec"
	"sync"
	"testing"
)

// Real output, measured on this platform by running `installer -verboseR`
// against a package built with pkgbuild. Not invented, because the whole
// value of parsing the installer's own account of itself is that it is the
// installer's rather than a guess made from outside.
const measuredInstallerOutput = `installer: Package name is Probe
installer: Installing at base path /Users/yesveer
installer:PHASE:Preparing for installation…
installer:PHASE:Preparing the disk…
installer:PHASE:Preparing Probe…
installer:PHASE:Waiting for other installations to complete…
installer:PHASE:Configuring the installation…
installer:STATUS:
installer:%97.750000
installer:STATUS:
installer:PHASE:Finishing the Installation…
installer:STATUS:
installer:%100.000000
installer:PHASE:The software was successfully installed.
installer: The install was successful.
`

// collectProgress runs a command through the parser and returns what it
// reported, guarded because the sink is called from the reading goroutine.
func collectProgress(t *testing.T, cmd *exec.Cmd) ([]Progress, string, error) {
	t.Helper()
	var (
		mu   sync.Mutex
		got  []Progress
		sink = func(p Progress) { mu.Lock(); got = append(got, p); mu.Unlock() }
	)
	SetProgressSink(sink)
	t.Cleanup(func() { SetProgressSink(nil) })

	out, err := runWithProgress(cmd)
	mu.Lock()
	defer mu.Unlock()
	return append([]Progress(nil), got...), out, err
}

func TestThePercentagesInstallerPrintsAreReported(t *testing.T) {
	reports, out, err := collectProgress(t,
		exec.Command("/bin/echo", "-n", measuredInstallerOutput))
	if err != nil {
		t.Fatal(err)
	}
	if out == "" {
		t.Error("the installer's output was not collected; a failure would " +
			"have nothing to explain itself with")
	}

	var percents []float64
	for _, p := range reports {
		if p.Total > 0 {
			percents = append(percents, float64(p.Done)/float64(p.Total)*100)
		}
	}
	if len(percents) == 0 {
		t.Fatal("no progress was reported from output that contains two percentages")
	}
	if last := percents[len(percents)-1]; last != 100 {
		t.Errorf("the last percentage reported is %v, want 100", last)
	}

	// 97.75 must survive as 97.75 and not be rounded away to 97 — the
	// scale exists so a fractional percentage stays a fractional one.
	found := false
	for _, v := range percents {
		if v > 97.7 && v < 97.8 {
			found = true
		}
	}
	if !found {
		t.Errorf("97.75%% was not reported faithfully; got %v", percents)
	}
}

// The phase is what somebody reads while the percentage is still absent.
// A package prints several phases before its first number, and those
// seconds are exactly when a motionless bar reads as a hang.
func TestThePhaseIsReportedBeforeAnyPercentageArrives(t *testing.T) {
	reports, _, err := collectProgress(t,
		exec.Command("/bin/echo", "-n", measuredInstallerOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) == 0 {
		t.Fatal("nothing was reported")
	}
	if reports[0].Phase != "Preparing for installation…" {
		t.Errorf("first phase reported is %q", reports[0].Phase)
	}
	if reports[0].Done != 0 {
		t.Errorf("the first phase reported %d done, before any percentage arrived",
			reports[0].Done)
	}
}

// A percentage with no phase line since the last one keeps the words that
// were there, or the label would blank out between the two.
func TestAPercentageKeepsTheWordsThatCameBeforeIt(t *testing.T) {
	reports, _, err := collectProgress(t,
		exec.Command("/bin/echo", "-n", measuredInstallerOutput))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range reports {
		if p.Done > 0 && p.Phase == "" {
			t.Fatalf("a percentage was reported with no words: %+v", p)
		}
	}
}

// Nothing to parse is not a failure: the bar stays indeterminate, which is
// what honest ignorance looks like.
func TestOutputWithNoProgressInItReportsNothing(t *testing.T) {
	reports, out, err := collectProgress(t,
		exec.Command("/bin/echo", "-n", "installer: something went wrong\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Errorf("progress was invented from output that contains none: %+v", reports)
	}
	if out == "" {
		t.Error("the output was dropped, so a failure could not be explained")
	}
}
