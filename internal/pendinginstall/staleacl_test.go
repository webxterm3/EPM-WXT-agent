//go:build darwin

package pendinginstall

import "testing"

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
