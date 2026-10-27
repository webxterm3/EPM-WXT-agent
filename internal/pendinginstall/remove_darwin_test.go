//go:build darwin

package pendinginstall

import (
	"os"
	"path/filepath"
	"testing"
)

func intoTempApplicationsWithTrash(t *testing.T) (apps, home string) {
	t.Helper()
	root := t.TempDir()
	apps = filepath.Join(root, "Applications")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}
	original := applicationsDir
	applicationsDir = apps
	t.Cleanup(func() { applicationsDir = original })

	// Home directories somewhere the test may write.
	home = filepath.Join(root, "Users")
	origUsers := usersDir
	usersDir = home
	t.Cleanup(func() { usersDir = origUsers })

	origChown := chownTree
	chownTree = func(string, string) error { return nil }
	t.Cleanup(func() { chownTree = origChown })
	return apps, home
}

// An uninstall must not ask for a password. Dragging to the Trash means
// deleting a directory out of /Applications, which a standard user cannot
// do, so Finder asks — the prompt this product exists to remove.
func TestRemovingAnApplicationDoesNotNeedThePerson(t *testing.T) {
	apps, home := intoTempApplicationsWithTrash(t)
	bundle := makeBundle(t, apps, "Slack.app", "1.0")

	if err := RemoveBundle(bundle, "tester"); err != nil {
		t.Fatalf("could not remove the application: %v", err)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Error("the application is still in the Applications folder")
	}

	// To the Trash, never deleted: somebody who removes the wrong thing has
	// a way back that they already know.
	inTrash := filepath.Join(home, "tester", ".Trash", "Slack.app")
	if _, err := os.Stat(inTrash); err != nil {
		t.Errorf("the application is not in the Trash either — an uninstall "+
			"that cannot be undone is a much larger promise: %v", err)
	}
}

// A second removal of the same name must not overwrite the first, the way
// Finder numbers them.
func TestASecondRemovalDoesNotOverwriteTheFirst(t *testing.T) {
	apps, home := intoTempApplicationsWithTrash(t)

	first := makeBundle(t, apps, "Slack.app", "1.0")
	if err := RemoveBundle(first, "tester"); err != nil {
		t.Fatal(err)
	}
	second := makeBundle(t, apps, "Slack.app", "2.0")
	if err := RemoveBundle(second, "tester"); err != nil {
		t.Fatal(err)
	}

	trash := filepath.Join(home, "tester", ".Trash")
	for _, want := range []string{"Slack.app", "Slack 2.app"} {
		if _, err := os.Stat(filepath.Join(trash, want)); err != nil {
			t.Errorf("%s is not in the Trash: %v", want, err)
		}
	}
}

// The agent must never be removable by the people it manages.
//
// A REAL bundle, in the real applications directory this run is using. A
// test that points at a path with nothing behind it passes whether the guard
// exists or not, because the move fails for its own reasons.
func TestTheAgentCannotBeRemovedThisWay(t *testing.T) {
	apps, _ := intoTempApplicationsWithTrash(t)
	bundle := makeBundle(t, apps, "wxt-agent.app", "1.0")

	if err := RemoveBundle(bundle, "tester"); err == nil {
		t.Fatal("the agent agreed to move itself to the Trash, so the people " +
			"it manages can switch it off")
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Error("the agent is gone from the Applications folder")
	}
}

// The request file is writable by any account on the machine by design, so a
// path from outside the Applications folder is refused rather than acted on.
func TestOnlyApplicationsCanBeRemoved(t *testing.T) {
	intoTempApplicationsWithTrash(t)

	// Real bundles, outside the applications folder. Pointing at paths with
	// nothing behind them passes whether the guard exists or not.
	elsewhere := t.TempDir()
	for _, name := range []string{"Important.app", "Payroll.app"} {
		path := makeBundle(t, elsewhere, name, "1.0")
		if err := RemoveBundle(path, "tester"); err == nil {
			t.Errorf("agreed to remove %s, which is not in the applications folder", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was moved anyway", path)
		}
	}

	// And something that is not an application bundle at all.
	notAnApp := filepath.Join(elsewhere, "notes.txt")
	if err := os.WriteFile(notAnApp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBundle(notAnApp, "tester"); err == nil {
		t.Error("agreed to remove a file that is not an application")
	}
}

// Nobody at the screen means nowhere to put it.
func TestRemovalNeedsSomebodyToOwnTheTrash(t *testing.T) {
	apps, _ := intoTempApplicationsWithTrash(t)
	bundle := makeBundle(t, apps, "Slack.app", "1.0")

	if err := RemoveBundle(bundle, ""); err == nil {
		t.Error("removed an application with nobody logged in to own the Trash")
	}
}
