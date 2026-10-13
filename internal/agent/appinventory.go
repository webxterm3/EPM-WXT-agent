package agent

import (
	"context"
	"encoding/json"
	"runtime"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
)

// appInventoryInterval is how often the machine's installed software is
// re-scanned on its own.
//
// Software is installed and removed on the order of days, so a frequent scan
// buys nothing and costs a filesystem and registry walk on somebody's laptop —
// a macOS bundle scan takes several seconds of real I/O. Once a day is the
// right cadence for a list that changes weekly; anything an operator needs
// sooner than that, they ask for with "Scan now" in the portal.
const appInventoryInterval = 24 * time.Hour

// appInventoryMinGap is the shortest time between two scans the agent starts
// by itself.
//
// The loop lives for the lifetime of ONE connection and scans as soon as it
// starts, so without this a machine on a flaky network re-scans every time it
// reconnects — which on a bad afternoon is far more often than the interval
// above, quietly undoing it. A manual scan from the portal is deliberately not
// subject to this: somebody asked.
const appInventoryMinGap = time.Hour

// appInventoryScanTimeout bounds one scan.
//
// A machine with a very large number of installed packages, or a stalled
// filesystem, must not leave a scan running forever holding its collector.
const appInventoryScanTimeout = 10 * time.Minute

// InventoryScanCommandID asks the agent to scan its installed software now,
// instead of waiting out appInventoryInterval.
//
// It must match the constant the backend sends; the drift test in the
// backend's store package reads this file to check that it still does.
const InventoryScanCommandID = "__vsay_inventory_scan__"

// requestInventoryScan asks the inventory loop to run a scan now.
//
// The send is non-blocking onto a buffered channel of one, which coalesces on
// purpose: an operator clicking "Scan now" five times, or five operators
// clicking once, must cost one scan and not five filesystem walks queued up
// behind each other on somebody's laptop.
func (a *Agent) requestInventoryScan() {
	select {
	case a.inventoryScanNow <- struct{}{}:
	default:
		a.logger.Info("App inventory: a scan is already pending, ignoring the request")
	}
}

// appInventoryLoop reports the machine's installed applications.
//
// This is the foundation of application control: a policy about software
// cannot be written, and cannot be reasoned about before it is enforced,
// without first knowing what is actually out there.
//
// It is sent as StatusUpdate(ReportDiscriminator, json) over the existing gRPC
// stream, the same route as __agent_stats__ and __access_snapshot__, so it
// needs no proto change. The payload is a snapshot rather than a stream of
// changes because neither platform offers reliable install notifications, and
// because a full list lets the backend reconcile idempotently — a repeat after
// an agent restart produces no duplicates.
//
// Runs for the connection lifetime: an offline machine has nowhere to send a
// scan, and the first thing that happens on reconnect is a fresh one.
func (a *Agent) appInventoryLoop(ctx context.Context) {
	collector := appinventory.PlatformCollector()
	if collector == nil {
		a.logger.Info("App inventory: no collector for this platform")
		return
	}

	ticker := time.NewTicker(appInventoryInterval)
	defer ticker.Stop()

	// The scan-on-connect, skipped when one has just run. The timestamp lives
	// on the agent rather than in this function because the function is
	// restarted on every reconnect, which is exactly the case it guards.
	if since := time.Since(a.lastInventoryScan()); since < appInventoryMinGap {
		a.logger.Info("App inventory: skipping the scan on connect, one ran recently",
			zap.Duration("ago", since.Round(time.Second)))
	} else {
		a.reportAppInventory(ctx, collector)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reportAppInventory(ctx, collector)
		case <-a.inventoryScanNow:
			// Deliberately shares the loop rather than scanning in its own
			// goroutine: one collector, one scan at a time. Two concurrent
			// walks would race to report, and the later-finishing one would
			// decide what counts as removed.
			a.logger.Info("App inventory: scan requested from the portal")
			a.reportAppInventory(ctx, collector)
		}
	}
}

// lastInventoryScan reports when a scan last finished. Zero before the first.
func (a *Agent) lastInventoryScan() time.Time {
	a.inventoryMu.Lock()
	defer a.inventoryMu.Unlock()
	return a.inventoryLastScan
}

// reportAppInventory runs one scan and sends it.
func (a *Agent) reportAppInventory(ctx context.Context, collector appinventory.Collector) {
	defer func() {
		a.inventoryMu.Lock()
		a.inventoryLastScan = time.Now()
		a.inventoryMu.Unlock()
	}()

	scanCtx, cancel := context.WithTimeout(ctx, appInventoryScanTimeout)
	defer cancel()

	started := time.Now()
	apps, collectErr := collector.Collect(scanCtx)

	snapshot := appinventory.Snapshot{
		CollectedAt: time.Now().UTC(),
		OS:          runtime.GOOS,
		Apps:        apps,
	}

	snapshotID := appinventory.NewSnapshotID()
	reports := snapshot.Chunk(snapshotID, appinventory.DefaultChunkSize)

	// A failed or truncated scan is reported as such on every chunk. The
	// backend refuses its removal sweep when it sees this, because a partial
	// scan must never be mistaken for "all this software is gone" — that would
	// turn one crashed agent into a machine that looks wiped.
	collectErrText := ""
	if collectErr != nil {
		collectErrText = collectErr.Error()
	}

	sent := 0
	for _, report := range reports {
		if ctx.Err() != nil {
			return
		}
		report.AgentVersion = BuildVersion
		report.CollectError = collectErrText

		payload, err := json.Marshal(report)
		if err != nil {
			a.logger.Warn("App inventory: could not encode a report", zap.Error(err))
			return
		}
		if err := a.grpcClient.SendStatusUpdate(appinventory.ReportDiscriminator, string(payload)); err != nil {
			// Stopping here rather than carrying on is deliberate: a snapshot
			// missing its final chunk leaves the backend's previous inventory
			// untouched, which is the safe outcome. Sending later chunks
			// without earlier ones would not be.
			a.logger.Debug("App inventory: send failed",
				zap.Int("chunk", report.Chunk), zap.Error(err))
			return
		}
		sent++
	}

	a.logger.Info("App inventory reported",
		zap.String("collector", collector.Name()),
		zap.Int("applications", len(apps)),
		zap.Int("chunks", sent),
		zap.Duration("scan_took", time.Since(started)),
		zap.String("collect_error", collectErrText))
}
