package agentstatus

import (
	"os"
	"path/filepath"
	"testing"
)

// progressInTemp points the status path at a directory this test owns.
func progressInTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	was := pathOverride
	pathOverride = filepath.Join(dir, "status.json")
	t.Cleanup(func() { pathOverride = was })
	if err := PrepareInstallProgress(); err != nil {
		t.Fatal(err)
	}
}

func TestAProgressReportSurvivesTheTrip(t *testing.T) {
	progressInTemp(t)

	ReportInstallProgress(InstallProgress{
		Application: "Slack", Phase: "Copying Slack", Done: 50_000_000, Total: 200_000_000,
	})

	got, ok := ReadInstallProgress()
	if !ok {
		t.Fatal("nothing came back")
	}
	if got.Application != "Slack" || got.Phase != "Copying Slack" {
		t.Errorf("got %q / %q", got.Application, got.Phase)
	}
	if got.Percent != 25 {
		t.Errorf("percent = %v, want 25", got.Percent)
	}
}

// A size nobody could measure must leave the bar sweeping rather than
// freezing it at zero, which reads as stuck.
func TestAnUnmeasurableInstallReportsNoPercentage(t *testing.T) {
	progressInTemp(t)
	ReportInstallProgress(InstallProgress{Application: "Zoom", Phase: "Preparing…"})

	got, ok := ReadInstallProgress()
	if !ok {
		t.Fatal("nothing came back")
	}
	if got.Percent >= 0 {
		t.Errorf("percent = %v, want a negative value meaning 'not measurable'", got.Percent)
	}
}

// ditto writes extended attributes and resource forks that a size walk does
// not count, so the destination really does end up bigger than the source
// was measured to be. A bar that overshoots to 112% is a bar nobody believes
// again.
func TestABarNeverOvershoots(t *testing.T) {
	progressInTemp(t)
	ReportInstallProgress(InstallProgress{Application: "VLC", Done: 112, Total: 100})

	got, _ := ReadInstallProgress()
	if got.Percent != 100 {
		t.Errorf("percent = %v, want it clamped to 100", got.Percent)
	}
}

// Cleared, not left at 100%: a finished line would otherwise be drawn under
// the name of whatever is installed next.
func TestAFinishedInstallLeavesNothingBehind(t *testing.T) {
	progressInTemp(t)
	ReportInstallProgress(InstallProgress{Application: "Slack", Done: 10, Total: 10})
	ClearInstallProgress()

	if _, ok := ReadInstallProgress(); ok {
		t.Error("a finished install is still reporting progress")
	}
}

// The menu bar runs as the logged-in user and only ever READS this. A file
// any account could write is a file any account could use to put words of
// its own on somebody's screen.
func TestOnlyTheAgentCanWriteProgress(t *testing.T) {
	progressInTemp(t)
	fi, err := os.Stat(installProgressPath())
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o022 != 0 {
		t.Errorf("install-progress is mode %04o — writable by somebody other "+
			"than the agent, who could then choose what the panel says", mode)
	}
}
