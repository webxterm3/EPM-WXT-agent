//go:build darwin

package pendinginstall

import (
	"strings"
	"testing"
	"time"
)

// The window must let somebody PUT an application in, and nothing else.
//
// delete_child would also let them remove applications that are already
// installed — a different and much larger thing than adding one, and not
// something anybody asked for by downloading an installer.
func TestTheWindowIsAddOnly(t *testing.T) {
	for _, forbidden := range []string{"delete", "delete_child", "write", "writeattr", "chown"} {
		if strings.Contains(aclRights, forbidden) {
			t.Errorf("the grant includes %q — somebody with an approved installer "+
				"could use the window to remove applications instead", forbidden)
		}
	}
	for _, needed := range []string{"add_file", "add_subdirectory"} {
		if !strings.Contains(aclRights, needed) {
			t.Errorf("the grant is missing %q, so the drag would still fail", needed)
		}
	}
}

// One directory, named as a constant. A grant that could be pointed anywhere
// is a grant that will eventually be pointed somewhere else.
func TestOnlyApplicationsIsEverGranted(t *testing.T) {
	if applicationsDir != "/Applications" {
		t.Errorf("the grant targets %q", applicationsDir)
	}
}

// Opened on every scan for as long as an approved installer sits there, so
// opening twice must not write the ACL twice — a duplicate entry is one the
// matching revoke would not remove.
func TestOpeningTwiceOnlyGrantsOnce(t *testing.T) {
	resetGrants(t)

	calls := 0
	swapACL(t, func(string, string, bool) error { calls++; return nil })

	if err := GrantDragInstall("someone"); err != nil {
		t.Fatal(err)
	}
	if err := GrantDragInstall("someone"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("the ACL was written %d times for one window — a duplicate entry "+
			"would survive the revoke that matches only one", calls)
	}
}

// A window has to close. The expiry is what stops a person who downloads an
// installer and never uses it from keeping write access until the agent
// restarts.
func TestAWindowExpires(t *testing.T) {
	resetGrants(t)

	revokes := 0
	swapACL(t, func(_, _ string, add bool) error {
		if !add {
			revokes++
		}
		return nil
	})

	if err := GrantDragInstall("someone"); err != nil {
		t.Fatal(err)
	}

	// Not yet.
	ExpireDragGrants()
	if revokes != 0 {
		t.Fatal("a fresh window was closed immediately")
	}

	// Wind the clock past it.
	dragMu.Lock()
	dragGrants["someone"] = time.Now().Add(-time.Second)
	dragMu.Unlock()

	ExpireDragGrants()
	if revokes != 1 {
		t.Errorf("an expired window was not closed (%d revokes)", revokes)
	}
}

// A stopped agent is exactly when nothing is watching, so nothing may be
// left open.
func TestEverythingClosesOnShutdown(t *testing.T) {
	resetGrants(t)

	revoked := map[string]bool{}
	swapACL(t, func(_, user string, add bool) error {
		if !add {
			revoked[user] = true
		}
		return nil
	})

	for _, u := range []string{"a", "b", "c"} {
		if err := GrantDragInstall(u); err != nil {
			t.Fatal(err)
		}
	}
	RevokeAllDragGrants()

	for _, u := range []string{"a", "b", "c"} {
		if !revoked[u] {
			t.Errorf("%s still had write access to /Applications after shutdown", u)
		}
	}
	if len(dragGrants) != 0 {
		t.Errorf("%d grants were still recorded as open", len(dragGrants))
	}
}

func TestAnEmptyUserIsNeverGranted(t *testing.T) {
	resetGrants(t)
	swapACL(t, func(string, string, bool) error {
		t.Fatal("the ACL was written for an unnamed user")
		return nil
	})
	if err := GrantDragInstall(""); err == nil {
		t.Error("a grant with no user succeeded")
	}
}

func resetGrants(t *testing.T) {
	t.Helper()
	dragMu.Lock()
	dragGrants = map[string]time.Time{}
	dragMu.Unlock()
}

// swapACL stands in for the chmod, so these tests say what the logic does
// without changing permissions on the machine running them.
func swapACL(t *testing.T, fn func(dir, user string, add bool) error) {
	t.Helper()
	orig := applyACL
	applyACL = fn
	t.Cleanup(func() { applyACL = orig })
}
