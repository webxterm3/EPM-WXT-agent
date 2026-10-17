package appinventory

import (
	"context"
	"os"
	"testing"
	"time"
)

// The collector enforcement uses must report every field a policy can match
// on. Anything it drops is a rule that silently matches nothing on the
// endpoint while the portal and the diagnostic say it matches.
//
// This is pinned as an invariant rather than a scan result because the bug it
// guards against was invisible: enforcement ran with signature reading turned
// off, the publisher came back empty for half the applications on the machine,
// and the only symptom was that nothing happened.
func TestEnforcementCollectorDropsNothingAPolicyMatchesOn(t *testing.T) {
	if os.Getenv("EPM_SMOKE") == "" {
		t.Skip("set EPM_SMOKE=1 to scan this machine")
	}
	full, _ := PlatformCollector().Collect(context.Background())
	fast, _ := FastPlatformCollector().Collect(context.Background())

	index := func(apps []Application) map[string]Application {
		m := make(map[string]Application, len(apps))
		for _, a := range apps {
			m[a.ID] = a
		}
		return m
	}
	f, s := index(full), index(fast)

	var blind int
	for id, a := range f {
		got, ok := s[id]
		if !ok {
			t.Errorf("%q is missing from the enforcement scan entirely", a.Name)
			continue
		}
		// The four fields MatchCriteria can constrain.
		if a.Publisher != "" && got.Publisher == "" {
			blind++
			if blind <= 3 {
				t.Errorf("%q: publisher is %q to the portal and empty to the enforcer",
					a.Name, a.Publisher)
			}
		}
		if a.Name != got.Name || a.BundleID != got.BundleID || a.InstallPath != got.InstallPath {
			t.Errorf("%q differs between the two scans", a.Name)
		}
	}
	if blind > 0 {
		t.Fatalf("%d applications would never match a publisher rule on the endpoint", blind)
	}
}

// The cache is what makes one collector affordable for a loop that runs every
// couple of minutes. Without it the honest collector is too slow to use and
// the temptation to make a blind one comes straight back.
func TestSignatureCacheMakesARescanCheap(t *testing.T) {
	if os.Getenv("EPM_SMOKE") == "" {
		t.Skip("set EPM_SMOKE=1 to scan this machine")
	}
	c := &DarwinCollector{}

	start := time.Now()
	first, _ := c.Collect(context.Background())
	cold := time.Since(start)

	start = time.Now()
	second, _ := c.Collect(context.Background())
	warm := time.Since(start)

	t.Logf("cold %s, warm %s, %d applications", cold.Round(time.Millisecond), warm.Round(time.Millisecond), len(first))
	if len(first) != len(second) {
		t.Fatalf("the two scans disagree: %d then %d", len(first), len(second))
	}
	if warm > cold/2 {
		t.Errorf("a warm rescan took %s against a cold %s — the cache is not working", warm, cold)
	}
	// And the publisher must survive the cache, which is the field the whole
	// exercise is about.
	for _, a := range second {
		if a.BundleID == "com.apple.TextEdit" && a.Publisher == "" {
			t.Error("the cached scan lost the publisher")
		}
	}
}

// A signature the collector could not read must not be remembered.
//
// codesign can fail for reasons that have nothing to do with the bundle — a
// cancelled context, a machine under load, the enclosing scan timing out — and
// it reports all of them the same way it reports an unsigned bundle: an empty
// authority. Caching that would make one bad moment permanent for that
// application, and the symptom would be the publisher bug all over again: a
// field the portal can see and the endpoint cannot.
func TestAFailedSignatureReadIsNotCached(t *testing.T) {
	if _, err := os.Stat("/System/Applications/TextEdit.app"); err != nil {
		t.Skip("no bundle to probe")
	}
	c := &DarwinCollector{}

	// A cancelled context: codesign cannot run, so the answer is empty.
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if got := c.signatureFor(dead, "/System/Applications/TextEdit.app"); got != "" {
		t.Fatalf("expected an empty answer from a cancelled read, got %q", got)
	}

	c.sigMu.Lock()
	_, cached := c.sigCache["/System/Applications/TextEdit.app"]
	c.sigMu.Unlock()
	if cached {
		t.Fatal("the failed read was cached; this application's publisher would stay empty for ever")
	}

	// And a real read afterwards still finds it.
	if got := c.signatureFor(context.Background(), "/System/Applications/TextEdit.app"); got == "" {
		t.Error("the signature could not be read even with a live context")
	}
}
