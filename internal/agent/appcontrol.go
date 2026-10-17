package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appcontrol"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// EnforcementDiscriminator is the StatusUpdate tag carrying what application
// control actually did on this machine.
//
// It must match the constant the backend routes on; the drift test in the
// backend's store package reads this file to check that it still does.
const EnforcementDiscriminator = "__app_enforcement__"

// enforcementFlushInterval is how often anything the enforcer did is sent.
//
// Batched rather than sent per event because a blocked application that
// relaunches itself produces a burst, and because these are a record for an
// operator to read later rather than something anybody is waiting on.
const enforcementFlushInterval = 30 * time.Second

// enforcementReport is the payload the backend receives.
type enforcementReport struct {
	ReportedAt   time.Time          `json:"reported_at"`
	AgentVersion string             `json:"agent_version"`
	Mechanism    string             `json:"mechanism"`
	Events       []appcontrol.Event `json:"events"`
}

// startAppControl brings up enforcement for this machine.
//
// Given the agent's own context rather than a connection's. The policy was
// written to disk when it arrived, so a machine that loses the network keeps
// enforcing what it was last told rather than quietly opening up — which is
// both what anybody would assume and the difference between a control and a
// suggestion.
//
// The reporting loop runs alongside it on the same context and simply does
// nothing while there is nowhere to send to; the enforcer's queue holds what
// happened meanwhile.
func (a *Agent) startAppControl(ctx context.Context) {
	if a.appControl == nil {
		return
	}
	go a.appControl.Run(ctx)
	go a.enforcementReportLoop(ctx)
}

// newAppControl builds the enforcer. Separate from startAppControl so the
// enforcer exists — and can be asked to release its locks — before any
// connection is made.
func (a *Agent) newAppControl(stateDir string) {
	a.appControl = appcontrol.New(appcontrol.Options{
		Logger:   a.logger,
		StateDir: stateDir,
		Policy: func() *apppolicy.Effective {
			if a.policies == nil {
				return nil
			}
			return a.policies.Current()
		},
	})
}

// enforcementReportLoop sends what the enforcer did.
func (a *Agent) enforcementReportLoop(ctx context.Context) {
	t := time.NewTicker(enforcementFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.flushEnforcementEvents()
		}
	}
}

func (a *Agent) flushEnforcementEvents() {
	if a.appControl == nil || a.grpcClient == nil {
		return
	}
	events := a.appControl.Drain()
	if len(events) == 0 {
		return
	}

	payload, err := json.Marshal(enforcementReport{
		ReportedAt:   time.Now().UTC(),
		AgentVersion: BuildVersion,
		Mechanism:    a.appControl.Mechanism(),
		Events:       events,
	})
	if err != nil {
		a.logger.Warn("Application control: could not encode its activity report", zap.Error(err))
		return
	}

	if err := a.grpcClient.SendStatusUpdate(EnforcementDiscriminator, string(payload)); err != nil {
		// The events are already drained and are not put back. They are a
		// record of something that has happened, and the agent's own log has
		// the same lines — requeueing them would mean an offline machine
		// accumulating a backlog it eventually drops anyway.
		a.logger.Debug("Application control: could not report its activity", zap.Error(err))
	}
}

// appControlStateDir is where the enforcer keeps its lock record: beside the
// policy it is enforcing.
func appControlStateDir(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Dir(configPath)
}
