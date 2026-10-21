package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// AppPolicyCommandID carries the machine's effective application-control
// policy from the portal.
//
// It must match the constant the backend sends; the drift test in the
// backend's store package reads this file to check that it still does.
const AppPolicyCommandID = "__vsay_apppolicy__"

// appPolicyFile is where the last received policy is kept.
//
// Beside the agent's config rather than inside it: the policy is pushed
// machinery that can arrive many times a day, and rewriting (and re-encrypting)
// the whole config document for each one would risk the enrolment data that
// file holds.
const appPolicyFile = "app-policy.json"

// policyStore holds the policy this machine is currently under.
//
// Kept in memory for the hot path — every process start consults it — and
// written to disk so a machine keeps the policy it was given across a restart
// rather than running unpoliced until its next connect.
type policyStore struct {
	mu     sync.RWMutex
	policy *apppolicy.Effective
	path   string
	logger *zap.Logger
}

func newPolicyStore(dir string, logger *zap.Logger) *policyStore {
	s := &policyStore{logger: logger}
	if dir != "" {
		s.path = filepath.Join(dir, appPolicyFile)
	}
	s.loadFromDisk()
	return s
}

// Current returns the policy in force, or nil when none has ever arrived.
//
// nil is meaningful and is not the same as an empty policy: a machine that has
// never been told anything must not be treated as one told "allow nothing".
func (s *policyStore) Current() *apppolicy.Effective {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

// Apply records a newly received policy.
func (s *policyStore) Apply(raw string) error {
	var eff apppolicy.Effective
	if err := json.Unmarshal([]byte(raw), &eff); err != nil {
		return err
	}

	s.mu.Lock()
	s.policy = &eff
	s.mu.Unlock()

	s.saveToDisk(raw)
	return nil
}

func (s *policyStore) saveToDisk(raw string) {
	if s.path == "" {
		return
	}
	// 0600: the policy names what this machine may and may not run, which is
	// a map of what to avoid for anybody reading it.
	if err := os.WriteFile(s.path, []byte(raw), 0o600); err != nil {
		// Worth continuing: the policy applies now even if it will not survive
		// a reboot, and the reason is on the record.
		s.logger.Error("App policy: applied but could not be saved — it will be lost on restart",
			zap.String("path", s.path), zap.Error(err))
	}
}

func (s *policyStore) loadFromDisk() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path) // #nosec G304 -- a path this agent chose
	if err != nil {
		// Absent is the normal state before the first push.
		return
	}

	var eff apppolicy.Effective
	if err := json.Unmarshal(raw, &eff); err != nil {
		// A corrupt file is dropped rather than half-applied. The backend
		// pushes the current policy on every connect, so the gap is one
		// reconnect long.
		s.logger.Warn("App policy: the stored policy could not be read, waiting for the next push",
			zap.Error(err))
		return
	}

	s.mu.Lock()
	s.policy = &eff
	s.mu.Unlock()
}

// handleAppPolicy applies a policy pushed from the portal.
func (a *Agent) handleAppPolicy(payload string) {
	if a.policies == nil {
		return
	}
	if err := a.policies.Apply(payload); err != nil {
		a.logger.Error("App policy: could not read the pushed policy", zap.Error(err))
		return
	}

	eff := a.policies.Current()

	// Stamped here, where policy actually arrived — not on the heartbeat that
	// rewrites the status file every few seconds. "Last synced" has to mean
	// the last time a policy came down, or it answers a different question
	// to the one the menu bar asks.
	now := time.Now()
	a.policySyncedAt.Store(&now)
	a.policyRules.Store(int64(len(eff.Rules)))
	mode := eff.Mode
	a.policyMode.Store(&mode)
	a.publishStatus(a.connected.Load(), "")

	a.logger.Info("App policy: updated",
		zap.String("mode", eff.Mode),
		zap.String("default_action", eff.DefaultAction),
		zap.Int("rules", len(eff.Rules)),
		// Said out loud on every push. "mode=audit" is the difference between
		// a policy that watches and one that acts, and it is the first thing
		// anybody reading these logs needs to know.
		zap.Bool("enforcing", eff.Mode == apppolicy.ModeEnforce))

	// Applied now rather than at the next tick. An operator who has just
	// pressed Save is watching the machine, and two minutes of nothing
	// happening reads as the policy not having arrived.
	if a.appControl != nil {
		a.appControl.Kick()
	}
}

// PolicyRequestDiscriminator asks the backend to push this machine's policy.
//
// Agent-to-server, which is the safe direction. The reverse — a new
// server-to-agent command id — is not safe in this product: handleCommand
// matches a fixed list and then falls through to running the payload through a
// shell, so any agent predating a new id would EXECUTE what was sent to it.
// The backend ignores discriminators it does not know, so an old backend
// simply does nothing with this.
const PolicyRequestDiscriminator = "__policy_request__"

// syncRequestPoll is how often a pressed button is noticed.
//
// A stat of one local file, so the cost is nothing and the only consideration
// is how long somebody stares at a menu before deciding it did not work. The
// status heartbeat would have done the job at fifteen seconds and felt broken.
const syncRequestPoll = time.Second

// syncRequestLoop watches for the menu bar's "sync now" and asks the backend
// for a fresh policy.
//
// The request carries nothing but the agent's identity. What a sync means, and
// whether this machine may have one, is decided entirely by the backend — so a
// user who can write the request file gains nothing they could not have by
// waiting for the next push.
func (a *Agent) syncRequestLoop(ctx context.Context) {
	ticker := time.NewTicker(syncRequestPoll)
	defer ticker.Stop()

	// The agent creates the file the menu bar writes into, because the menu
	// bar cannot: /var/log/vsay belongs to root so the agent's own log is not
	// writable by every user on the machine, and creating a file there needs
	// permission on the directory. Writing INTO an existing file does not.
	//
	// This also drops anything left from a previous run. A press that went
	// unanswered because the agent was stopping should not fire on the next
	// start, long after whoever pressed it stopped caring.
	if err := agentstatus.PrepareSyncRequest(); err != nil {
		// Said once, at Warn: the button will fail for everyone on this
		// machine and the menu bar can only report what it sees from the
		// other side.
		a.logger.Warn("Could not prepare the sync-request file — the menu bar's "+
			"Sync Now will not work on this machine", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			agentstatus.ClearSyncRequest()
			return
		case <-ticker.C:
			if !agentstatus.TakeSyncRequest() {
				continue
			}
			a.requestPolicyPush()
		}
	}
}

// requestPolicyPush asks the backend to send this machine's policy now.
func (a *Agent) requestPolicyPush() {
	client := a.grpcSafe()
	if client == nil {
		// Offline. Saying so in the log matters because the menu bar cannot:
		// it reads a file and has no idea whether the request was answered.
		a.logger.Info("App policy: a sync was requested but the agent is not connected")
		return
	}
	if err := client.SendStatusUpdate(PolicyRequestDiscriminator, "{}"); err != nil {
		a.logger.Warn("App policy: could not ask for a sync", zap.Error(err))
		return
	}
	a.logger.Info("App policy: sync requested")
}
