package appcontrol

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// removeRule is a policy that blocks name AND asks for it to be moved aside.
func removeRule(mode, name string) *apppolicy.Effective {
	p := blockRule(mode, name)
	p.Rules[0].RemoveBlocked = true
	return p
}

// fakeApp lays out something that looks like an installed application.
func fakeApp(t *testing.T, root, name string) (dir, binary string) {
	t.Helper()
	dir = filepath.Join(root, name+".app")
	macOS := filepath.Join(dir, "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}
	binary = filepath.Join(macOS, name)
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, binary
}

func TestQuarantineMovesTheApplicationAndPutsItBack(t *testing.T) {
	apps := t.TempDir()
	state := t.TempDir()
	dir, binary := fakeApp(t, apps, "Chrome")

	inventory := []appinventory.Application{{
		ID: "a", Name: "Chrome", InstallPath: dir, ExePath: binary,
	}}
	pol := removeRule(apppolicy.ModeEnforce, "Chrome")

	e := New(Options{
		StateDir: state, Policy: func() *apppolicy.Effective { return pol },
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: inventory},
	})

	e.Reconcile(context.Background())

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the blocked application is still where the user left it")
	}
	// Moved, not deleted. This is the property the whole design rests on.
	held := quarantinePath(state, dir)
	if _, err := os.Stat(held); err != nil {
		t.Fatalf("the application was not found in quarantine at %s: %v", held, err)
	}

	// Withdraw the rule: it comes back, in one piece, where it was.
	pol = &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
	e.Reconcile(context.Background())

	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("the application was not restored to %s: %v", binary, err)
	}
	if _, err := os.Stat(held); !os.IsNotExist(err) {
		t.Error("a copy was left behind in quarantine")
	}
}

// Uninstalling the agent must give back everything it is holding. Software
// this product moved and then forgot about is the worst outcome available.
func TestUninstallRestoresQuarantinedApplications(t *testing.T) {
	apps := t.TempDir()
	state := t.TempDir()
	dir, binary := fakeApp(t, apps, "Chrome")

	e := New(Options{
		StateDir: state,
		Policy:   func() *apppolicy.Effective { return removeRule(apppolicy.ModeEnforce, "Chrome") },
		Procs:    &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: []appinventory.Application{{
			ID: "a", Name: "Chrome", InstallPath: dir, ExePath: binary,
		}}},
	})
	e.Reconcile(context.Background())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("setup: nothing was quarantined")
	}

	e.Release()

	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("uninstalling the agent left the application missing: %v", err)
	}
	if e.HeldCount() != 0 {
		t.Errorf("the agent still claims to hold %d application(s) after releasing", e.HeldCount())
	}
}

// A quarantine record has to survive a restart, or the application is left
// missing with nothing that knows where it went.
func TestQuarantineSurvivesARestart(t *testing.T) {
	apps := t.TempDir()
	state := t.TempDir()
	dir, binary := fakeApp(t, apps, "Chrome")
	inventory := []appinventory.Application{{ID: "a", Name: "Chrome", InstallPath: dir, ExePath: binary}}

	first := New(Options{
		StateDir: state,
		Policy:   func() *apppolicy.Effective { return removeRule(apppolicy.ModeEnforce, "Chrome") },
		Procs:    &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: inventory},
	})
	first.Reconcile(context.Background())

	// A new agent, same state directory, policy now says nothing.
	second := New(Options{
		StateDir: state,
		Policy: func() *apppolicy.Effective {
			return &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
		},
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: inventory},
	})
	second.Reconcile(context.Background())

	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("a restarted agent did not restore the application: %v", err)
	}
}

// Audit mode must not move anybody's software. This is the same promise as
// for locking, and it matters more here because a move is visible.
func TestAuditModeNeverQuarantines(t *testing.T) {
	apps := t.TempDir()
	dir, _ := fakeApp(t, apps, "Chrome")

	e := New(Options{
		StateDir: t.TempDir(),
		Policy:   func() *apppolicy.Effective { return removeRule(apppolicy.ModeAudit, "Chrome") },
		Procs:    &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: []appinventory.Application{{
			ID: "a", Name: "Chrome", InstallPath: dir,
		}}},
	})
	e.Reconcile(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Error("audit mode moved an application; it must never act")
	}
}

// A policy with no matching rule must not be able to sweep a machine into
// quarantine through its catch-all.
func TestTheDefaultActionNeverQuarantines(t *testing.T) {
	apps := t.TempDir()
	dir, _ := fakeApp(t, apps, "Chrome")

	e := New(Options{
		StateDir: t.TempDir(),
		Policy: func() *apppolicy.Effective {
			// Block everything, by default, with no rules at all.
			return &apppolicy.Effective{
				Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionBlock,
			}
		},
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: &fakeCollector{apps: []appinventory.Application{{
			ID: "a", Name: "Chrome", InstallPath: dir,
		}}},
	})
	e.Reconcile(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Error("the policy default moved an application into quarantine; only a rule may ask for that")
	}
}

// Protected system paths are never moved, whatever a rule says. Moving one is
// not a mistake that can be undone by changing the policy afterwards.
func TestQuarantineRefusesProtectedPaths(t *testing.T) {
	state := t.TempDir()
	for _, p := range protectedSample() {
		if _, err := quarantine(state, Target{Name: "x", Path: p}); err == nil {
			t.Errorf("quarantine(%q) was allowed; the machine would not boot to a desktop", p)
		}
	}
}

// An application that reappears at its original path — a reinstall — must not
// be overwritten by the copy we are holding.
func TestQuarantineDoesNotOverwriteAReinstall(t *testing.T) {
	apps := t.TempDir()
	state := t.TempDir()
	dir, binary := fakeApp(t, apps, "Chrome")

	if _, err := quarantine(state, Target{Name: "Chrome", Path: dir}); err != nil {
		t.Fatal(err)
	}
	// The user reinstalls it, with different contents so the two copies are
	// distinguishable.
	fakeApp(t, apps, "Chrome")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho new\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Releasing must leave the user's copy alone rather than putting ours back
	// over it.
	if err := release(state, dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "#!/bin/sh\necho new\n" {
		t.Error("the reinstalled copy was overwritten by the quarantined one")
	}
}

// liveCollector reports what is ACTUALLY on disk, re-reading every call.
//
// The frozen slice that fakeCollector returns is why the self-undoing
// quarantine shipped: it kept reporting an application that had already been
// moved away, so the reconcile pass never saw the state the real collector
// would have reported, and the bug was invisible to every test.
type liveCollector struct{ root string }

func (liveCollector) Name() string { return "live" }

func (c liveCollector) Collect(context.Context) ([]appinventory.Application, error) {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return nil, err
	}
	var apps []appinventory.Application
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".app") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".app")
		dir := filepath.Join(c.root, e.Name())
		apps = append(apps, appinventory.Application{
			ID: name, Name: name, InstallPath: dir,
			ExePath:   filepath.Join(dir, "Contents", "MacOS", name),
			Publisher: "Acme Ltd",
		})
	}
	return apps, nil
}

// A quarantined application must STAY quarantined across repeated passes.
//
// It cannot: once moved, it is gone from every place a collector looks, so a
// pass that derives "what should be blocked" purely from the inventory
// concludes it is no longer blocked and puts it back. The install watcher then
// sees the directory change and fires again. The result was somebody's
// application moving back and forth every few seconds.
func TestQuarantineSurvivesRepeatedPasses(t *testing.T) {
	apps := t.TempDir()
	state := t.TempDir()
	dir, binary := fakeApp(t, apps, "Chrome")

	pol := removeRule(apppolicy.ModeEnforce, "Chrome")
	e := New(Options{
		StateDir: state, Policy: func() *apppolicy.Effective { return pol },
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: liveCollector{root: apps},
	})

	for pass := 1; pass <= 5; pass++ {
		e.Reconcile(context.Background())
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("pass %d: the application is back at %s — the quarantine undid itself", pass, dir)
		}
		if e.HeldCount() != 1 {
			t.Fatalf("pass %d: the agent is holding %d application(s), want 1", pass, e.HeldCount())
		}
	}

	// And it is still released when the policy genuinely stops blocking it.
	pol = &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
	e.Reconcile(context.Background())
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("the application was not restored once the rule was withdrawn: %v", err)
	}
	if e.HeldCount() != 0 {
		t.Errorf("still holding %d application(s) after release", e.HeldCount())
	}
}

// Somebody reinstalling past a block has to be visible. The refusal to
// overwrite the held copy is correct; swallowing it is not.
func TestAReinstalledApplicationLeavesAgain(t *testing.T) {
	apps := t.TempDir()
	state := t.TempDir()
	dir, _ := fakeApp(t, apps, "Chrome")

	pol := removeRule(apppolicy.ModeEnforce, "Chrome")
	e := New(Options{
		StateDir: state, Policy: func() *apppolicy.Effective { return pol },
		Procs: &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Collector: liveCollector{root: apps},
	})
	e.Reconcile(context.Background())
	e.Drain()

	// The user puts it back.
	reinstalled, _ := fakeApp(t, apps, "Chrome")
	e.Reconcile(context.Background())
	e.Drain()

	// It has to LEAVE again.
	//
	// This used to assert only that the reinstall was REPORTED, and the
	// implementation satisfied that by refusing — it would not overwrite the
	// copy it already held, so it emitted a failure and left the application
	// installed. The report was accurate and the outcome was the thing the
	// policy exists to prevent: a blocked application sitting on the machine,
	// taking space, for as long as somebody kept putting it back.
	if _, err := os.Stat(reinstalled); !os.IsNotExist(err) {
		t.Fatal("a reinstalled application stayed on the machine; being told about " +
			"it is not the same as it being gone")
	}

	// And the copy taken the first time must still be there. Removing the
	// application is recoverable only because nothing is ever deleted.
	// Walked rather than globbed: the held copy sits under the whole of its
	// original path, which in a test is a temporary directory nobody can
	// write a pattern for.
	var held []string
	_ = filepath.Walk(filepath.Join(state, quarantineDirName),
		func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() && strings.HasPrefix(filepath.Base(path), "Chrome") {
				held = append(held, path)
			}
			return nil
		})

	if len(held) == 0 {
		t.Fatal("nothing was kept; a quarantine that deletes is not recoverable")
	}
	if len(held) < 2 {
		t.Errorf("only %d copy was kept. The first quarantine and the reinstall are "+
			"two different builds of the application, and overwriting one with the "+
			"other is the data loss this design exists to avoid", len(held))
	}
	_ = dir
}
