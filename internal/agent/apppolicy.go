package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"

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
	a.logger.Info("App policy: updated",
		zap.String("mode", eff.Mode),
		zap.String("default_action", eff.DefaultAction),
		zap.Int("rules", len(eff.Rules)),
		// Said out loud on every push. "mode=audit" is the difference between
		// a policy that watches and one that acts, and it is the first thing
		// anybody reading these logs needs to know.
		zap.Bool("enforcing", eff.Mode == apppolicy.ModeEnforce))
}
