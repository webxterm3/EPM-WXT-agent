package agent

import (
	"testing"
	"time"
)

// The cadence is a product decision, not an implementation detail: it is what
// an operator is told in the portal ("once a day") and what the backend's
// staleness window is sized against.
func TestScanCadenceIsOncePerDay(t *testing.T) {
	if appInventoryInterval != 24*time.Hour {
		t.Errorf("appInventoryInterval = %v, want 24h — the portal tells operators once a day", appInventoryInterval)
	}
}

// A reconnect must not be a back door around the interval. The loop restarts
// on every connection and scans as it starts, so without a gap a machine on a
// flaky network scans far more often than once a day.
func TestTheReconnectGapIsShorterThanTheInterval(t *testing.T) {
	if appInventoryMinGap <= 0 {
		t.Fatal("appInventoryMinGap must be positive, or every reconnect re-scans")
	}
	if appInventoryMinGap >= appInventoryInterval {
		t.Errorf("appInventoryMinGap (%v) >= interval (%v): the scheduled scan would be suppressed by its own predecessor",
			appInventoryMinGap, appInventoryInterval)
	}
}

// A scan has to finish well inside the gap, or a slow machine could still be
// scanning when the next one is allowed to start.
func TestOneScanFitsInsideTheGap(t *testing.T) {
	if appInventoryScanTimeout >= appInventoryMinGap {
		t.Errorf("a scan may run for %v but the gap is only %v", appInventoryScanTimeout, appInventoryMinGap)
	}
}

// The timestamp is written whatever happens, including on a failed scan.
// Recording it only on success would let a machine whose scan keeps failing
// retry on every single reconnect.
func TestScanTimeIsRecordedEvenWhenTheScanFails(t *testing.T) {
	a := &Agent{}
	if !a.lastInventoryScan().IsZero() {
		t.Fatal("a fresh agent should have no recorded scan")
	}

	// reportAppInventory records the time in a deferred call, so a nil
	// collector — the cheapest possible failure — still updates it.
	func() {
		defer func() { _ = recover() }()
		a.reportAppInventory(nil, nil)
	}()

	if a.lastInventoryScan().IsZero() {
		t.Error("a failed scan left no timestamp; every reconnect would retry it")
	}
}
