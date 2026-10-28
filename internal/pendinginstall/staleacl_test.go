//go:build darwin

package pendinginstall

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// Real `ls -lde /Applications` output, with the entry this package writes.
const listingWithOurGrant = `drwxrwxr-x@ 42 root  admin  1344 25 Oct 02:07 /Applications
 0: user:yesveer allow add_file,add_subdirectory
`

// A grant left behind survives a reboot — it is on the directory, not in
// memory — so an agent that was killed leaves a standing write permission on
// /Applications that nothing is watching.
func TestAWindowLeftOpenByACrashedAgentIsClosedOnTheNextStart(t *testing.T) {
	if got := usersWithRights(listingWithOurGrant, aclRights); len(got) != 1 || got[0] != "yesveer" {
		t.Fatalf("did not find the left-behind grant: %v", got)
	}
}

// Rights coalesce into ONE entry per user, so an entry carrying anything
// else is not one this package can claim to have written. Removing somebody
// else's deliberate grant is worse than leaving ours.
func TestAWiderGrantSomebodyElseMadeIsLeftAlone(t *testing.T) {
	listing := `drwxrwxr-x@ 42 root  admin  1344 25 Oct 02:07 /Applications
 0: user:someone allow add_file,add_subdirectory,delete_child
 1: user:other allow write,delete
`
	if got := usersWithRights(listing, aclRights); len(got) != 0 {
		t.Errorf("would have stripped rights this package never granted: %v", got)
	}
}

// Group entries are not ours either: this package only ever names a user.
func TestGroupEntriesAreNotTouched(t *testing.T) {
	listing := `drwxrwxr-x@ 42 root  admin  1344 25 Oct 02:07 /Applications
 0: group:staff allow add_file,add_subdirectory
`
	if got := usersWithRights(listing, aclRights); len(got) != 0 {
		t.Errorf("would have stripped a group entry: %v", got)
	}
}

// A directory with no entries at all is the ordinary case.
func TestNothingIsRevokedWhenNothingWasLeft(t *testing.T) {
	listing := "drwxrwxr-x@ 42 root  admin  1344 25 Oct 02:07 /Applications\n"
	if got := usersWithRights(listing, aclRights); len(got) != 0 {
		t.Errorf("invented a grant out of an empty listing: %v", got)
	}
}

// macOS does not promise the order it prints rights in.
func TestRightsAreComparedAsASetNotAString(t *testing.T) {
	listing := `drwxrwxr-x@ 42 root  admin  1344 25 Oct 02:07 /Applications
 0: user:yesveer allow add_subdirectory,add_file
`
	if got := usersWithRights(listing, aclRights); len(got) != 1 {
		t.Errorf("the same two rights in the other order were not recognised: %v", got)
	}
}

// The refusal has to say what was already tried.
//
// "operation not permitted" on /Applications, as root, is not SIP — the
// directory carries no restricted flag and is absent from rootless.conf.
// Granting App Management was the obvious explanation and it was tried on a
// real machine; it changed nothing. A message that still recommends it would
// send the next person down a road already walked.
func TestTheRefusalSaysWhatWasAlreadyTried(t *testing.T) {
	err := describeACLFailure("/Applications", "yesveer", "+a",
		syscall.EPERM, "chmod: Failed to set ACL on file '/Applications': Operation not permitted")
	if err == nil {
		t.Fatal("a refusal was reported as success")
	}

	msg := err.Error()
	for _, want := range []string{"/Applications", "own session", "menu bar"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not mention %q: %s", want, msg)
		}
	}
	// It must not send somebody after a permission that has been shown not
	// to help.
	if strings.Contains(msg, "System Settings") {
		t.Error("the message still points at a System Settings switch that was " +
			"tried and made no difference")
	}
}

// Something that is NOT a permission refusal must not be blamed on one.
func TestAnotherFailureIsReportedAsItself(t *testing.T) {
	err := describeACLFailure("/Applications", "nobody", "+a",
		errors.New("exit status 1"), "chmod: No such file or directory")
	if strings.Contains(err.Error(), "App Management") {
		t.Errorf("an unrelated failure was blamed on a permission: %s", err)
	}
}

// And the grant path must use the explanation, not a bare errno.
func TestTheGrantPathUsesTheExplanation(t *testing.T) {
	b, err := os.ReadFile("dragdrop_darwin.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func setRights(")
	if i < 0 {
		t.Fatal("setRights is gone")
	}
	body := src[i:]
	if j := strings.Index(body[1:], "\nfunc "); j >= 0 {
		body = body[:j+1]
	}

	if !strings.Contains(body, "describeACLFailure(") {
		t.Error("the grant path returns a bare errno, so the message nobody " +
			"can act on is the one they get")
	}
	// And it must try the session before giving up — that is the one thing
	// left that has not been ruled out.
	if !strings.Contains(body, "asuser") {
		t.Error("the entry is only ever asked for from a background service " +
			"with no session, which is the case macOS is most willing to " +
			"refuse outright")
	}
}

// A refusal from a background service must be asked again from inside the
// user's session before it is believed.
//
// A LaunchDaemon runs as root with no session attached, and that is the case
// macOS is most willing to refuse outright — no prompt, no row in System
// Settings, just EPERM. It is the one explanation left that has not been
// ruled out: granting App Management by hand was tried on a real machine and
// changed nothing.
func TestARefusalIsAskedAgainFromTheUsersSession(t *testing.T) {
	original, origUID := runChmod, consoleUIDFn
	var attempts [][]string
	runChmod = func(_ context.Context, prefix []string, args ...string) ([]byte, error) {
		attempts = append(attempts, prefix)
		if len(prefix) == 0 {
			return []byte("Operation not permitted"), syscall.EPERM
		}
		return nil, nil // the session attempt succeeds
	}
	consoleUIDFn = func() int { return 501 }
	t.Cleanup(func() { runChmod, consoleUIDFn = original, origUID })

	if err := setRights("/Applications", "yesveer", "add_file", true); err != nil {
		t.Fatalf("the entry was refused even though the session attempt worked: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("made %d attempts, wanted the plain one then the session one", len(attempts))
	}
	if len(attempts[0]) != 0 {
		t.Error("the first attempt was not the plain one")
	}
	if len(attempts[1]) == 0 || attempts[1][0] != "/bin/launchctl" {
		t.Errorf("the second attempt was %v, not one made inside the session", attempts[1])
	}
}

// And when the plain attempt works, nothing else is tried.
func TestNothingExtraIsRunWhenTheEntryIsAccepted(t *testing.T) {
	original := runChmod
	calls := 0
	runChmod = func(context.Context, []string, ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	t.Cleanup(func() { runChmod = original })

	if err := setRights("/Applications", "yesveer", "add_file", true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("ran %d processes for an entry macOS accepted first time", calls)
	}
}
