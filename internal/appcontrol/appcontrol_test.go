package appcontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// --- stand-ins -------------------------------------------------------------

type fakeProcs struct{ procs []RunningProcess }

func (f *fakeProcs) List(context.Context) ([]RunningProcess, error) { return f.procs, nil }

type fakeKiller struct {
	killed []int
	fail   bool
}

func (f *fakeKiller) Kill(pid int) error {
	if f.fail {
		return errors.New("nope")
	}
	f.killed = append(f.killed, pid)
	return nil
}

type fakeLocker struct {
	locked   map[string]bool
	lockErr  error
	unlocked []string
}

func newFakeLocker() *fakeLocker { return &fakeLocker{locked: map[string]bool{}} }

func (f *fakeLocker) Kind() string { return "fake" }
func (f *fakeLocker) Lock(t Target) error {
	if f.lockErr != nil {
		return f.lockErr
	}
	f.locked[t.Path] = true
	return nil
}
func (f *fakeLocker) Unlock(t Target) error {
	delete(f.locked, t.Path)
	f.unlocked = append(f.unlocked, t.Path)
	return nil
}

type fakeCollector struct{ apps []appinventory.Application }

func (f *fakeCollector) Name() string { return "fake" }
func (f *fakeCollector) Collect(context.Context) ([]appinventory.Application, error) {
	return f.apps, nil
}

// blockRule builds a policy that blocks everything named name.
func blockRule(mode, name string) *apppolicy.Effective {
	return &apppolicy.Effective{
		Mode:          mode,
		DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{{
			PolicyName: "Browsers", Scope: "tenant", Mode: mode,
			Rule: apppolicy.Rule{
				ID: "r1", Name: "No " + name, Enabled: true,
				Action: apppolicy.ActionBlock,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpEquals, Values: []string{name}},
				},
			},
		}},
	}
}

func newTestEnforcer(t *testing.T, pol *apppolicy.Effective, procs *fakeProcs,
	killer *fakeKiller, locker *fakeLocker, apps []appinventory.Application) *Enforcer {
	t.Helper()
	return New(Options{
		StateDir:  t.TempDir(),
		Policy:    func() *apppolicy.Effective { return pol },
		Procs:     procs,
		Killer:    killer,
		Locker:    locker,
		Collector: &fakeCollector{apps: apps},
	})
}

// --- the no-op guarantees --------------------------------------------------

// Audit mode is the whole safety story of the rollout: a policy can be written,
// pushed and watched without anything on anybody's machine changing. If this
// test ever fails, the "nothing is enforced yet" promise in the portal is a lie.
func TestAuditModeTouchesNothing(t *testing.T) {
	procs := &fakeProcs{procs: []RunningProcess{{PID: 42, ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome"}}}
	killer := &fakeKiller{}
	locker := newFakeLocker()
	apps := []appinventory.Application{{
		ID: "a", Name: "Chrome", InstallPath: "/Applications/Chrome.app",
		ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome",
	}}

	e := newTestEnforcer(t, blockRule(apppolicy.ModeAudit, "Chrome"), procs, killer, locker, apps)
	e.Reconcile(context.Background())
	e.sweepProcesses(context.Background())

	if len(killer.killed) != 0 {
		t.Errorf("audit mode terminated pids %v; it must never act", killer.killed)
	}
	if len(locker.locked) != 0 {
		t.Errorf("audit mode locked %v; it must never act", locker.locked)
	}
}

func TestNoPolicyTouchesNothing(t *testing.T) {
	procs := &fakeProcs{procs: []RunningProcess{{PID: 42, ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome"}}}
	killer := &fakeKiller{}
	locker := newFakeLocker()

	e := newTestEnforcer(t, nil, procs, killer, locker, nil)
	e.Reconcile(context.Background())
	e.sweepProcesses(context.Background())

	if len(killer.killed) != 0 || len(locker.locked) != 0 {
		t.Error("a machine that has never been given a policy must be left alone")
	}
}

// --- enforcement actually happening ---------------------------------------

func TestEnforceModeTerminatesABlockedApplication(t *testing.T) {
	procs := &fakeProcs{procs: []RunningProcess{
		{PID: 42, ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome"},
		{PID: 43, ExePath: "/Applications/Slack.app/Contents/MacOS/Slack"},
	}}
	killer := &fakeKiller{}
	apps := []appinventory.Application{
		{ID: "a", Name: "Chrome", InstallPath: "/Applications/Chrome.app",
			ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome"},
		{ID: "b", Name: "Slack", InstallPath: "/Applications/Slack.app",
			ExePath: "/Applications/Slack.app/Contents/MacOS/Slack"},
	}

	e := newTestEnforcer(t, blockRule(apppolicy.ModeEnforce, "Chrome"), procs, killer, newFakeLocker(), apps)
	e.Reconcile(context.Background())
	e.sweepProcesses(context.Background())

	if len(killer.killed) != 1 || killer.killed[0] != 42 {
		t.Fatalf("killed %v, want only pid 42 (Chrome)", killer.killed)
	}

	events := e.Drain()
	if len(events) == 0 {
		t.Fatal("terminating an application reported nothing; the audit trail is the point")
	}
	var found bool
	for _, ev := range events {
		if ev.Mechanism == MechanismTerminate && ev.AppName == "Chrome" && ev.Rule == "No Chrome" {
			found = true
		}
	}
	if !found {
		t.Errorf("no terminate event naming the rule; got %+v", events)
	}
}

// A browser is dozens of processes under one bundle, several levels inside it.
// A rule naming the browser has to match its own renderers, or blocking Chrome
// leaves every tab running.
func TestHelperProcessesInsideABundleAreMatchedAsTheOuterApplication(t *testing.T) {
	const helper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/" +
		"Versions/155.0/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)"

	procs := &fakeProcs{procs: []RunningProcess{
		{PID: 10, ExePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
		{PID: 11, ExePath: helper},
		{PID: 12, ExePath: helper},
	}}
	killer := &fakeKiller{}
	apps := []appinventory.Application{{
		ID: "a", Name: "Google Chrome", InstallPath: "/Applications/Google Chrome.app",
		ExePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	}}

	e := newTestEnforcer(t, blockRule(apppolicy.ModeEnforce, "Google Chrome"), procs, killer, newFakeLocker(), apps)
	e.Reconcile(context.Background())
	e.sweepProcesses(context.Background())

	if len(killer.killed) != 3 {
		t.Fatalf("killed %v, want all three Chrome processes including the nested helpers", killer.killed)
	}

	// One event for the application, not one per process.
	var terminates int
	for _, ev := range e.Drain() {
		if ev.Mechanism == MechanismTerminate {
			terminates++
		}
	}
	if terminates != 1 {
		t.Errorf("reported %d terminate events for one application; a browser would flood the trail", terminates)
	}
}

func TestBlockedApplicationIsLockedAndThenRestored(t *testing.T) {
	locker := newFakeLocker()
	apps := []appinventory.Application{{
		ID: "a", Name: "Chrome", InstallPath: "/Applications/Chrome.app",
		ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome",
	}}
	pol := blockRule(apppolicy.ModeEnforce, "Chrome")

	e := New(Options{
		StateDir:  t.TempDir(),
		Policy:    func() *apppolicy.Effective { return pol },
		Procs:     &fakeProcs{},
		Killer:    &fakeKiller{},
		Locker:    locker,
		Collector: &fakeCollector{apps: apps},
	})

	e.Reconcile(context.Background())
	if !locker.locked["/Applications/Chrome.app"] {
		t.Fatal("a blocked application was not prevented from launching")
	}

	// The rule goes away. The application must be put back: software this
	// product disabled and then forgot about is the worst outcome here.
	pol = &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
	e.Reconcile(context.Background())

	if locker.locked["/Applications/Chrome.app"] {
		t.Error("the application is still locked after the rule was withdrawn")
	}
	if len(locker.unlocked) != 1 {
		t.Errorf("unlocked %v, want exactly one restore", locker.unlocked)
	}
}

// Switching a policy back to audit must also release what enforce mode locked,
// or a machine stays locked down with nothing on the server saying it is.
func TestReturningToAuditModeReleasesExistingLocks(t *testing.T) {
	locker := newFakeLocker()
	apps := []appinventory.Application{{
		ID: "a", Name: "Chrome", InstallPath: "/Applications/Chrome.app",
		ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome",
	}}
	pol := blockRule(apppolicy.ModeEnforce, "Chrome")

	e := New(Options{
		StateDir: t.TempDir(), Policy: func() *apppolicy.Effective { return pol },
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: locker,
		Collector: &fakeCollector{apps: apps},
	})
	e.Reconcile(context.Background())
	if !locker.locked["/Applications/Chrome.app"] {
		t.Fatal("setup: nothing was locked")
	}

	pol = blockRule(apppolicy.ModeAudit, "Chrome")
	e.Reconcile(context.Background())

	if locker.locked["/Applications/Chrome.app"] {
		t.Error("audit mode left an enforce-mode lock in place")
	}
}

// Locks have to survive a restart, and so does knowing they were ours.
func TestLocksSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	apps := []appinventory.Application{{
		ID: "a", Name: "Chrome", InstallPath: "/Applications/Chrome.app",
		ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome",
	}}

	first := New(Options{
		StateDir: dir, Policy: func() *apppolicy.Effective { return blockRule(apppolicy.ModeEnforce, "Chrome") },
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: apps},
	})
	first.Reconcile(context.Background())

	// A new agent, same state directory, policy now says nothing.
	locker := newFakeLocker()
	second := New(Options{
		StateDir: dir,
		Policy: func() *apppolicy.Effective {
			return &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
		},
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: locker,
		Collector: &fakeCollector{apps: apps},
	})
	second.Reconcile(context.Background())

	if len(locker.unlocked) != 1 {
		t.Fatalf("a restarted agent restored %v; it must still know the lock was its own", locker.unlocked)
	}
}

// --- the guards ------------------------------------------------------------

func TestTheCircuitBreakerRefusesAnImplausiblePolicy(t *testing.T) {
	var apps []appinventory.Application
	for i := 0; i < maxBlockedPerPass+5; i++ {
		name := fmt.Sprintf("App%d", i)
		apps = append(apps, appinventory.Application{
			ID: name, Name: name,
			InstallPath: "/Applications/" + name + ".app",
			ExePath:     "/Applications/" + name + ".app/Contents/MacOS/" + name,
		})
	}

	// Block everything: the shape of a mis-saved rule, or a default-deny
	// policy saved against the wrong scope.
	pol := &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{{
			PolicyName: "Oops", Rule: apppolicy.Rule{
				Name: "everything", Enabled: true, Action: apppolicy.ActionBlock,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpContains, Values: []string{"App"}},
				},
			},
		}},
	}

	locker := newFakeLocker()
	e := newTestEnforcer(t, pol, &fakeProcs{}, &fakeKiller{}, locker, apps)
	e.Reconcile(context.Background())

	if len(locker.locked) != 0 {
		t.Fatalf("locked %d applications past the %d limit; one bad rule would brick a fleet",
			len(locker.locked), maxBlockedPerPass)
	}

	var refused bool
	for _, ev := range e.Drain() {
		if ev.Mechanism == MechanismRefused {
			refused = true
			if !strings.Contains(ev.Detail, "safety limit") {
				t.Errorf("the refusal does not explain itself: %q", ev.Detail)
			}
		}
	}
	if !refused {
		t.Error("the pass was refused silently; nobody would know the policy did not apply")
	}
}

// The agent must never be able to block itself: there would be nothing left
// running that could be told to undo it.
func TestTheAgentIsNeverBlocked(t *testing.T) {
	for _, path := range []string{
		"/usr/local/bin/wxt-agent",
		"/Applications/wxt-agent.app/Contents/MacOS/wxt-agent",
		`C:\ProgramData\vsay\wxt-agent.exe`,
	} {
		if !isOwnBinary(path) {
			t.Errorf("isOwnBinary(%q) = false; a policy could block the agent itself", path)
		}
	}
	if isOwnBinary("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome") {
		t.Error("an ordinary application was mistaken for the agent and would never be enforced")
	}
}

func TestProtectedPathsAreNeverEnforced(t *testing.T) {
	procs := &fakeProcs{procs: []RunningProcess{
		{PID: 1, ExePath: "/sbin/launchd"},
		{PID: 2, ExePath: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"},
	}}
	killer := &fakeKiller{}

	// A rule broad enough to catch them, which is what somebody writing
	// "block anything whose name contains 'n'" by accident produces.
	pol := &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionBlock,
	}

	e := newTestEnforcer(t, pol, procs, killer, newFakeLocker(), nil)
	e.sweepProcesses(context.Background())

	if len(killer.killed) != 0 {
		t.Fatalf("killed %v; system processes must be untouchable whatever the policy says", killer.killed)
	}
}

func TestRepeatedBlocksAreReportedOnce(t *testing.T) {
	procs := &fakeProcs{procs: []RunningProcess{
		{PID: 42, ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome"},
	}}
	apps := []appinventory.Application{{
		ID: "a", Name: "Chrome", InstallPath: "/Applications/Chrome.app",
		ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome",
	}}

	now := time.Now()
	e := New(Options{
		StateDir: t.TempDir(),
		Policy:   func() *apppolicy.Effective { return blockRule(apppolicy.ModeEnforce, "Chrome") },
		Procs:    procs, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: apps},
		Now:       func() time.Time { return now },
	})
	e.Reconcile(context.Background())
	e.Drain()

	// An application that relaunches itself every few seconds — a login item,
	// a crash-restarting helper — must not produce an event every poll.
	for i := 0; i < 20; i++ {
		e.sweepProcesses(context.Background())
	}
	if n := len(e.Drain()); n != 1 {
		t.Errorf("twenty sweeps produced %d events; the trail would be unreadable", n)
	}

	// Past the gap it reports again, so a block that is still happening an
	// hour later is still visible.
	now = now.Add(repeatEventGap + time.Second)
	e.sweepProcesses(context.Background())
	if n := len(e.Drain()); n != 1 {
		t.Errorf("after the gap elapsed, got %d events, want 1", n)
	}
}

// Something installed since the last scan still gets a decision. "We had not
// scanned it yet" is not a reason to run software the policy forbids.
func TestUnknownProgramsAreStillDecided(t *testing.T) {
	procs := &fakeProcs{procs: []RunningProcess{
		{PID: 99, ExePath: "/Applications/Chrome.app/Contents/MacOS/Chrome"},
	}}
	killer := &fakeKiller{}

	e := newTestEnforcer(t, blockRule(apppolicy.ModeEnforce, "Chrome"), procs, killer, newFakeLocker(), nil)
	e.sweepProcesses(context.Background())

	if len(killer.killed) != 1 {
		t.Errorf("killed %v; a program missing from the inventory must still be matched by name", killer.killed)
	}
}

// protectedSample is a handful of paths this platform must never act on, for
// tests that assert refusal rather than enumerate the whole list.
func protectedSample() []string {
	var out []string
	for _, p := range protectedPrefixes {
		out = append(out, p+"/Something.app")
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}
