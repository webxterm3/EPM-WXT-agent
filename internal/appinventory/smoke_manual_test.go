package appinventory

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSmokeRealMachine runs the real collector against this machine.
//
// Skipped unless EPM_SMOKE is set: it reads the actual filesystem, so it is a
// development aid rather than something CI can assert on.
func TestSmokeRealMachine(t *testing.T) {
	if os.Getenv("EPM_SMOKE") == "" {
		t.Skip("set EPM_SMOKE=1 to scan this machine")
	}
	c := FastPlatformCollector()
	if c == nil {
		t.Skip("no collector on this platform")
	}

	start := time.Now()
	apps, err := c.Collect(context.Background())
	t.Logf("collected %d applications in %s (err=%v)", len(apps), time.Since(start).Round(time.Millisecond), err)

	bySource := map[string]int{}
	for _, a := range apps {
		bySource[a.Source]++
	}
	for s, n := range bySource {
		t.Logf("  %-22s %d", s, n)
	}

	shown := 0
	for _, a := range apps {
		if a.Source == SourceHomebrew && shown < 6 {
			t.Logf("  brew: %-18s %-12s exe=%s", a.Name, a.Version, a.ExePath)
			shown++
		}
	}
	for _, a := range apps {
		if a.BundleID != "" {
			t.Logf("  app:  %-28s %s", a.Name, a.BundleID)
			break
		}
	}
}
