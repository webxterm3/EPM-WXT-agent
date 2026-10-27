//go:build darwin

package pendinginstall

import (
	"strings"
	"testing"
	"time"
)

// stubBundleACL records what would have been written, so a test never
// changes the permissions of anything in /Applications on the machine
// running it.
func stubBundleACL(t *testing.T) *[]string {
	t.Helper()
	original := applyBundleACL
	var wrote []string
	applyBundleACL = func(bundle, user string, add bool) error {
		verb := "revoke"
		if add {
			verb = "grant"
		}
		wrote = append(wrote, verb+" "+user+" "+bundle)
		return nil
	}
	t.Cleanup(func() {
		applyBundleACL = original
		dragMu.Lock()
		bundleGrants = map[string]time.Time{}
		dragMu.Unlock()
	})
	return &wrote
}

// THE guard. A removal grant is handed to a standard user, and the agent is
// what enforces policy on the machine — being able to drag it to the Trash
// would make every other rule optional. A policy rule allowing "wxt-agent",
// however it came to be written, must not reach this.
func TestTheAgentCannotBeMadeRemovable(t *testing.T) {
	wrote := stubBundleACL(t)

	for _, own := range []string{
		"/Applications/wxt-agent.app",
		"/applications/WXT-Agent.app",
		"/usr/local/bin/wxt-agent",
		"/Applications/wxt-agent.app/Contents/MacOS/wxt-agent",
	} {
		if err := GrantBundleRemoval("yesveer", own); err == nil {
			t.Errorf("granted permission to remove %s", own)
		}
	}
	if len(*wrote) != 0 {
		t.Errorf("wrote an entry anyway: %v", *wrote)
	}
}

// Ordinary software is removable when policy says so.
func TestAnAllowedApplicationBecomesRemovable(t *testing.T) {
	wrote := stubBundleACL(t)

	if err := GrantBundleRemoval("yesveer", "/Applications/Slack.app"); err != nil {
		t.Fatalf("could not allow Slack to be removed: %v", err)
	}
	if len(*wrote) != 1 || !strings.HasPrefix((*wrote)[0], "grant yesveer ") {
		t.Fatalf("wrote %v", *wrote)
	}

	// Re-asserted on every scan; only the first call changes anything.
	for i := 0; i < 5; i++ {
		_ = GrantBundleRemoval("yesveer", "/Applications/Slack.app")
	}
	if len(*wrote) != 1 {
		t.Errorf("rewrote the same entry %d times", len(*wrote))
	}
}

// An application that stops being allowed stops being removable at the next
// scan — not whenever a ten-minute window happens to run out, which would
// leave a rule change unapplied for long enough to act on.
func TestPermissionIsWithdrawnAsSoonAsPolicyChanges(t *testing.T) {
	wrote := stubBundleACL(t)

	_ = GrantBundleRemoval("yesveer", "/Applications/Slack.app")
	_ = GrantBundleRemoval("yesveer", "/Applications/Docker.app")

	// The rule allowing Docker is removed; Slack is still allowed.
	RevokeBundleGrantsExcept("yesveer", map[string]bool{"/Applications/Slack.app": true})

	var revoked []string
	for _, w := range *wrote {
		if strings.HasPrefix(w, "revoke ") {
			revoked = append(revoked, w)
		}
	}
	if len(revoked) != 1 || !strings.Contains(revoked[0], "Docker.app") {
		t.Fatalf("withdrew %v, wanted exactly Docker", revoked)
	}
}

// A grant belongs to one account, and is keyed on it.
//
// Two people can be logged into a Mac at once, and the grant is handed to
// whoever is at the screen. Revoking by bundle alone would take away a
// permission the other person still has — or, worse, report success while
// leaving an entry in place that nothing is tracking any more.
func TestRevokingAsTheWrongAccountTakesNothingAway(t *testing.T) {
	wrote := stubBundleACL(t)

	_ = GrantBundleRemoval("yesveer", "/Applications/Slack.app")
	RevokeBundleRemoval("someone-else", "/Applications/Slack.app")

	for _, w := range *wrote {
		if strings.HasPrefix(w, "revoke ") {
			t.Errorf("another account's revoke wrote %q", w)
		}
	}

	// And the real owner's grant is still tracked, so re-asserting it on the
	// next scan is still a no-op rather than a second write.
	before := len(*wrote)
	_ = GrantBundleRemoval("yesveer", "/Applications/Slack.app")
	if len(*wrote) != before {
		t.Error("the owner's grant was lost, and had to be written again")
	}
}
