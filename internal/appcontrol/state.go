package appcontrol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
)

// lockStateFile records what this agent has locked.
//
// It exists for one reason: an application this product disabled has to be
// restorable, and after a restart the only thing that knows a lock was ours —
// rather than something the machine already had — is this file. Without it the
// agent would either refuse to touch anything it did not lock in the current
// process (so a reboot leaves software permanently broken) or assume every
// lock is its own (so it would undo somebody else's).
const lockStateFile = "app-control-locks.json"

// lockRecord is one application this agent is preventing from launching.
type lockRecord struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	ExePath  string `json:"exe_path,omitempty"`
	BundleID string `json:"bundle_id,omitempty"`

	// Publisher is kept so a quarantined application can still be judged.
	//
	// Once it has been moved it is gone from the inventory, so the only
	// description of it left is this record — and a policy that names a
	// publisher has to be able to decide about it, or the application is
	// released the moment it is put away.
	Publisher string `json:"publisher,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Policy    string `json:"policy,omitempty"`

	// Quarantined distinguishes an application that was MOVED from one that
	// was merely locked. They are undone in completely different ways, and
	// getting it wrong means either an application left missing or an
	// execute bit restored on something that is not there.
	Quarantined bool `json:"quarantined,omitempty"`

	// Elevated marks a grant of administrator rights rather than a removal of
	// them. It shares this record, and therefore this restore discipline, for
	// one reason: a grant left behind after the policy stopped asking for it
	// is a permanent hole, and the only machinery that reliably withdraws
	// things here is the one that already withdraws locks.
	Elevated bool `json:"elevated,omitempty"`
}

type lockState struct {
	mu      sync.Mutex
	path    string
	logger  *zap.Logger
	records map[string]lockRecord
}

func newLockState(dir string, logger *zap.Logger) *lockState {
	s := &lockState{logger: logger, records: map[string]lockRecord{}}
	if dir != "" {
		s.path = filepath.Join(dir, lockStateFile)
	}
	s.load()
	return s
}

func (s *lockState) all() map[string]lockRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]lockRecord, len(s.records))
	for k, v := range s.records {
		out[k] = v
	}
	return out
}

func (s *lockState) get(key string) (lockRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[key]
	return r, ok
}

func (s *lockState) add(r lockRecord) {
	s.mu.Lock()
	s.records[r.Key] = r
	s.mu.Unlock()
	s.save()
}

func (s *lockState) remove(key string) {
	s.mu.Lock()
	delete(s.records, key)
	s.mu.Unlock()
	s.save()
}

func (s *lockState) save() {
	if s.path == "" {
		return
	}
	s.mu.Lock()
	list := make([]lockRecord, 0, len(s.records))
	for _, r := range s.records {
		list = append(list, r)
	}
	s.mu.Unlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	// Written through a temporary file: a half-written state file is a set of
	// locks nothing knows how to undo, which is the one failure here that
	// leaves a user's machine worse off with no way back.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		s.logger.Error("Application control: could not record which applications are locked",
			zap.String("path", s.path), zap.Error(err))
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		s.logger.Error("Application control: could not record which applications are locked",
			zap.String("path", s.path), zap.Error(err))
		_ = os.Remove(tmp)
	}
}

func (s *lockState) load() {
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path) // #nosec G304 -- a path this agent chose
	if err != nil {
		return
	}
	var list []lockRecord
	if err := json.Unmarshal(data, &list); err != nil {
		// Unreadable state means locks that cannot be attributed. They are
		// left alone rather than guessed at in either direction, and the next
		// reconcile re-locks whatever the policy still blocks.
		s.logger.Warn("Application control: the lock record could not be read; existing locks will be left as they are",
			zap.Error(err))
		return
	}
	s.mu.Lock()
	for _, r := range list {
		s.records[r.Key] = r
	}
	s.mu.Unlock()
}
