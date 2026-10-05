package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/config"
	"github.com/Yesveer/wxt-agent/internal/logship"
)

// LogShipCommandID is the command the backend sends to turn system-log
// collection on or off, or to change what is collected. Its payload is a JSON
// config.LogShippingConfig.
//
// It goes over the existing mTLS gRPC command channel, the same route as CA
// rotation and self-update, so it needs no new endpoint and no second
// credential.
const LogShipCommandID = "__vsay_logship__"

// logShipRunner owns the collector's lifetime so it can be stopped and
// restarted when the settings change, without restarting the agent.
type logShipRunner struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	// parent is the agent-lifetime context new runs are derived from, so a
	// reconfigure cannot outlive the agent.
	parent context.Context
}

// startLogShipping begins collecting the machine's own system logs and sending
// them to the backend for archiving.
//
// It runs for the agent's whole lifetime rather than per gRPC connection: an
// offline machine keeps collecting, its bookmarks hold, and the backlog goes
// out when the link returns. Tying it to the connection would leave a gap
// exactly over an outage, which is when the logs matter most.
//
// Uploads go over HTTPS, not the gRPC stream. That stream carries interactive
// remote-control screen data, and a log backlog sharing it would stall
// somebody's live session.
func (a *Agent) startLogShipping(ctx context.Context) {
	a.logShip.mu.Lock()
	a.logShip.parent = ctx
	a.logShip.mu.Unlock()

	a.applyLogShipping(a.config.LogShipping)
}

// applyLogShipping stops any running collector and starts one for cfg.
func (a *Agent) applyLogShipping(cfg config.LogShippingConfig) {
	a.logShip.mu.Lock()
	defer a.logShip.mu.Unlock()

	if a.logShip.cancel != nil {
		a.logShip.cancel()
		a.logShip.cancel = nil
	}
	if a.logShip.parent == nil {
		// Settings arrived before the agent finished starting. The config has
		// already been stored, so the next start picks it up.
		return
	}
	if !cfg.Enabled {
		return
	}

	opts := logship.SourceOptions{
		SystemLogs:       cfg.SystemLogs,
		Websites:         cfg.Websites,
		WindowsChannels:  cfg.WindowsChannels,
		IncludeInfoDebug: cfg.IncludeInfoDebug,
		KeepRaw:          cfg.KeepRaw,
	}
	if !opts.Enabled() {
		// Enabled with nothing selected is a misconfiguration, not a reason to
		// run a collector that can never produce anything.
		a.logger.Warn("Log shipping is enabled but no sources are selected — nothing will be collected")
		return
	}

	sources := logship.PlatformSources(opts, a.logger)
	if len(sources) == 0 {
		a.logger.Info("Log shipping: no collector for this platform")
		return
	}

	shipper, err := logship.New(logShipConfig(cfg), sources, logship.NewHTTPUploader(
		a.pinnedCAHTTPClient(),
		a.config.Server.Host,
		a.config.Server.TokenHash,
		a.agentID,
	), a.logger)
	if err != nil {
		a.logger.Error("Log shipping could not start", zap.Error(err))
		return
	}

	runCtx, cancel := context.WithCancel(a.logShip.parent)
	a.logShip.cancel = cancel
	go shipper.Run(runCtx)
}

// logShipConfig translates the agent's settings into shipper settings.
func logShipConfig(cfg config.LogShippingConfig) logship.Config {
	out := logship.DefaultConfig(logBookmarkFile)

	if cfg.IntervalSeconds > 0 {
		out.Interval = time.Duration(cfg.IntervalSeconds) * time.Second
	}
	if cfg.BackfillHours > 0 {
		out.Backfill = time.Duration(cfg.BackfillHours) * time.Hour
	}
	switch {
	case cfg.DailyBudgetMB > 0:
		out.DailyBudgetBytes = int64(cfg.DailyBudgetMB) << 20
	case cfg.DailyBudgetMB < 0:
		out.DailyBudgetBytes = 0 // explicitly unlimited
	}
	return out
}

// handleLogShipConfig applies settings pushed from the portal.
//
// The settings are written to the agent's config file before taking effect, so
// a machine that reboots keeps collecting what it was told to. Applying them
// only in memory would silently revert every machine on its next restart.
func (a *Agent) handleLogShipConfig(payload string) {
	var cfg config.LogShippingConfig
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		a.logger.Error("Log shipping: could not read the pushed settings", zap.Error(err))
		return
	}

	a.config.LogShipping = cfg
	if err := a.persistConfig(); err != nil {
		// Worth continuing: collection should start now even if it will not
		// survive a reboot, and the reason is on the record.
		a.logger.Error("Log shipping: settings applied but could not be saved — they will be lost on restart",
			zap.Error(err))
	}

	a.logger.Info("Log shipping: settings updated",
		zap.Bool("enabled", cfg.Enabled),
		zap.Bool("system_logs", cfg.SystemLogs),
		zap.Bool("websites", cfg.Websites),
		zap.Int("daily_budget_mb", cfg.DailyBudgetMB))

	a.applyLogShipping(cfg)
}

// persistConfig writes the in-memory config back to disk.
func (a *Agent) persistConfig() error {
	if a.configPath == "" {
		return fmt.Errorf("the agent does not know where its config file is")
	}
	return config.SaveEncrypted(a.config, a.configPath)
}

// SetConfigPath tells the agent where its config file is.
//
// It is set from the command line rather than assumed, because the agent
// accepts a --config flag and writing settings back to a guessed default
// would leave the running agent and the file on disk disagreeing.
func (a *Agent) SetConfigPath(path string) { a.configPath = path }
