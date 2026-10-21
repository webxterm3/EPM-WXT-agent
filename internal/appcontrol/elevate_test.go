package appcontrol

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

type fakeElevator struct {
	granted map[string]bool
	revoked []string
	err     error
	support bool
}

func newFakeElevator() *fakeElevator {
	return &fakeElevator{granted: map[string]bool{}, support: true}
}

func (f *fakeElevator) Kind() string    { return "fake" }
func (f *fakeElevator) Supported() bool { return f.support }
func (f *fakeElevator) Allow(t Target) error {
	if f.err != nil {
		return f.err
	}
	f.granted[t.Path] = true
	return nil
}
func (f *fakeElevator) Revoke(t Target) error {
	delete(f.granted, t.Path)
	f.revoked = append(f.revoked, t.Path)
	return nil
}

func elevatePolicy(mode, name string) *apppolicy.Effective {
	return &apppolicy.Effective{
		Mode: mode, DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{{
			PolicyName: "Elevation", Mode: mode,
			Rule: apppolicy.Rule{
				Name: "Let " + name + " elevate", Enabled: true,
				Action: apppolicy.ActionElevate,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpEquals, Values: []string{name}},
				},
			},
		}},
	}
}

func elevatorEnforcer(t *testing.T, pol **apppolicy.Effective, el Elevator, apps []appinventory.Application) *Enforcer {
	t.Helper()
	return New(Options{
		StateDir: t.TempDir(),
		Policy:   func() *apppolicy.Effective { return *pol },
		Procs:    &fakeProcs{}, Killer: &fakeKiller{}, Locker: newFakeLocker(),
		Elevator:  el,
		Collector: &fakeCollector{apps: apps},
	})
}

func installerApp() []appinventory.Application {
	return []appinventory.Application{{
		ID: "a", Name: "Installer", InstallPath: "/Applications/Installer.app",
		ExePath: "/Applications/Installer.app/Contents/MacOS/Installer",
	}}
}

func TestElevationIsGrantedAndWithdrawn(t *testing.T) {
	el := newFakeElevator()
	pol := elevatePolicy(apppolicy.ModeEnforce, "Installer")
	e := elevatorEnforcer(t, &pol, el, installerApp())

	e.Reconcile(context.Background())
	if !el.granted["/Applications/Installer.app"] {
		t.Fatal("the rule did not grant elevation")
	}

	// The rule goes away: the grant must go with it. A grant that outlives
	// its policy is a permanent way to run something as administrator that
	// nobody is asking for any more.
	pol = &apppolicy.Effective{Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow}
	e.Reconcile(context.Background())

	if el.granted["/Applications/Installer.app"] {
		t.Error("the grant survived the rule being withdrawn")
	}
	if len(el.revoked) != 1 {
		t.Errorf("revoked %v, want exactly one withdrawal", el.revoked)
	}
}

func TestUninstallWithdrawsEveryElevation(t *testing.T) {
	el := newFakeElevator()
	pol := elevatePolicy(apppolicy.ModeEnforce, "Installer")
	e := elevatorEnforcer(t, &pol, el, installerApp())

	e.Reconcile(context.Background())
	if len(el.granted) != 1 {
		t.Fatal("setup: nothing was granted")
	}

	e.Release()

	if len(el.granted) != 0 {
		t.Error("uninstalling the agent left an elevation grant behind")
	}
	if e.HeldCount() != 0 {
		t.Errorf("still holding %d record(s) after release", e.HeldCount())
	}
}

func TestAuditModeGrantsNoElevation(t *testing.T) {
	el := newFakeElevator()
	pol := elevatePolicy(apppolicy.ModeAudit, "Installer")
	e := elevatorEnforcer(t, &pol, el, installerApp())

	e.Reconcile(context.Background())

	if len(el.granted) != 0 {
		t.Fatal("audit mode handed out administrator rights")
	}
}

// A platform that cannot elevate must SAY so, every time, for as long as the
// rule stands. Silence here is how the elevate action spent months being an
// advertised feature that did nothing.
func TestAnUnsupportedPlatformReportsItRatherThanSayingNothing(t *testing.T) {
	el := newFakeElevator()
	el.support = false
	el.err = errors.New("elevation is not available on this platform yet")

	pol := elevatePolicy(apppolicy.ModeEnforce, "Installer")
	e := elevatorEnforcer(t, &pol, el, installerApp())

	e.Reconcile(context.Background())

	var reported bool
	for _, ev := range e.Drain() {
		if ev.Mechanism == MechanismElevate && ev.Outcome == OutcomeFailed {
			reported = true
			if ev.Detail == "" {
				t.Error("the failure carries no reason")
			}
		}
	}
	if !reported {
		t.Fatal("an unsupported elevation was not reported; the portal would show the rule as working")
	}
}

// Elevating a handful of applications is a policy. Elevating a hundred is a
// rule that matched more than its author meant, and the result is a machine
// where most software runs as administrator.
func TestTheElevationCeilingRefusesAnImplausiblePolicy(t *testing.T) {
	var apps []appinventory.Application
	for i := 0; i < maxElevatedPerPass+3; i++ {
		name := fmt.Sprintf("App%d", i)
		apps = append(apps, appinventory.Application{
			ID: name, Name: name,
			InstallPath: "/Applications/" + name + ".app",
		})
	}

	pol := &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{{
			PolicyName: "Oops", Mode: apppolicy.ModeEnforce,
			Rule: apppolicy.Rule{
				Name: "everything", Enabled: true, Action: apppolicy.ActionElevate,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpContains, Values: []string{"App"}},
				},
			},
		}},
	}

	el := newFakeElevator()
	e := elevatorEnforcer(t, &pol, el, apps)
	e.Reconcile(context.Background())

	if len(el.granted) != 0 {
		t.Fatalf("granted elevation to %d applications past the limit of %d",
			len(el.granted), maxElevatedPerPass)
	}
	var refused bool
	for _, ev := range e.Drain() {
		if ev.Mechanism == MechanismRefused {
			refused = true
		}
	}
	if !refused {
		t.Error("the pass was refused silently; nobody would know the policy did not apply")
	}
}

// Blocking is still allowed to happen while elevation is refused? No — if the
// elevation ceiling trips, the whole pass is abandoned, because a policy that
// wrong should not have any of it applied.
func TestTheElevationCeilingAbandonsTheWholePass(t *testing.T) {
	var apps []appinventory.Application
	for i := 0; i < maxElevatedPerPass+3; i++ {
		name := fmt.Sprintf("App%d", i)
		apps = append(apps, appinventory.Application{ID: name, Name: name,
			InstallPath: "/Applications/" + name + ".app"})
	}
	apps = append(apps, appinventory.Application{
		ID: "blocked", Name: "Blocked", InstallPath: "/Applications/Blocked.app",
		ExePath: "/Applications/Blocked.app/Contents/MacOS/Blocked",
	})

	pol := &apppolicy.Effective{
		Mode: apppolicy.ModeEnforce, DefaultAction: apppolicy.ActionAllow,
		Rules: []apppolicy.EffectiveRule{
			{PolicyName: "Deny", Mode: apppolicy.ModeEnforce, Rule: apppolicy.Rule{
				Name: "block one", Enabled: true, Action: apppolicy.ActionBlock,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpEquals, Values: []string{"Blocked"}},
				},
			}},
			{PolicyName: "Oops", Mode: apppolicy.ModeEnforce, Rule: apppolicy.Rule{
				Name: "elevate everything", Enabled: true, Action: apppolicy.ActionElevate,
				Match: apppolicy.MatchCriteria{
					AppName: apppolicy.StringMatch{Op: apppolicy.OpContains, Values: []string{"App"}},
				},
			}},
		},
	}

	locker := newFakeLocker()
	el := newFakeElevator()
	e := New(Options{
		StateDir: t.TempDir(),
		Policy:   func() *apppolicy.Effective { return pol },
		Procs:    &fakeProcs{}, Killer: &fakeKiller{}, Locker: locker,
		Elevator: el, Collector: &fakeCollector{apps: apps},
	})
	e.Reconcile(context.Background())

	if len(locker.locked) != 0 {
		t.Errorf("the block was applied from a pass whose elevation ceiling tripped: %v", locker.locked)
	}
}
