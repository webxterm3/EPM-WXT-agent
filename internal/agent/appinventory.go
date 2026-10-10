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
// re-scanned.
//
// Software is installed and removed on the order of days, so a frequent scan
// buys nothing and costs a filesystem and registry walk on somebody's laptop.
// A scan also runs immediately on connect, so a change is picked up at the
// next reconnect rather than waiting out the full interval.
const appInventoryInterval = 12 * time.Hour

// appInventoryScanTimeout bounds one scan.
//
// A machine with a very large number of installed packages, or a stalled
// filesystem, must not leave a scan running forever holding its collector.
const appInventoryScanTimeout = 10 * time.Minute

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

	a.reportAppInventory(ctx, collector)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reportAppInventory(ctx, collector)
		}
	}
}

// reportAppInventory runs one scan and sends it.
func (a *Agent) reportAppInventory(ctx context.Context, collector appinventory.Collector) {
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
