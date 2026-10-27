package agentstatus

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Consuming the request is the remove itself, not a check followed by one.
// With a separate check, two passes of the agent's loop — or an agent and a
// restarting agent — both see the file and both act, so one press becomes two
// policy fetches.
func TestOneRequestIsTakenOnlyOnce(t *testing.T) {
	withTempStatusDir(t)

	if err := PrepareSyncRequest(); err != nil {
		t.Fatalf("the agent could not prepare the request file: %v", err)
	}
	if err := RequestSync(); err != nil {
		t.Fatalf("could not request a sync: %v", err)
	}

	if !TakeSyncRequest() {
		t.Fatal("the request that was just written was not seen")
	}
	if TakeSyncRequest() {
		t.Error("the same request was taken twice — one press would fetch policy twice")
	}
}

func TestNoRequestIsNotARequest(t *testing.T) {
	withTempStatusDir(t)
	if TakeSyncRequest() {
		t.Error("a sync was reported with no request file present")
	}
	if err := PrepareSyncRequest(); err != nil {
		t.Fatal(err)
	}
	if TakeSyncRequest() {
		t.Error("an empty request file was taken as a request — the agent would " +
			"sync on every tick for ever")
	}
}

func TestClearingDropsAPendingRequest(t *testing.T) {
	withTempStatusDir(t)
	if err := PrepareSyncRequest(); err != nil {
		t.Fatal(err)
	}
	if err := RequestSync(); err != nil {
		t.Fatal(err)
	}
	ClearSyncRequest()
	if TakeSyncRequest() {
		t.Error("a cleared request still fired — it would fetch policy on the next " +
			"start, long after whoever pressed it stopped caring")
	}
}

// The request must sit beside the status file. If the two directories ever
// diverge, the menu bar writes somewhere the agent never looks and the button
// does nothing at all — silently.
func TestTheRequestSitsBesideTheStatusFile(t *testing.T) {
	if got, want := filepath.Dir(syncRequestPath()), filepath.Dir(Path()); got != want {
		t.Errorf("request lives in %q but the agent owns %q", got, want)
	}
}

// withTempStatusDir points the package at a directory the test owns.
func withTempStatusDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig := pathOverride
	pathOverride = filepath.Join(dir, "status.json")
	t.Cleanup(func() { pathOverride = orig })
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// The directory belongs to root, because the agent's log is in it. The menu
// bar runs as the logged-in user and must never need to create or unlink
// anything there — the first version did, and failed with
// "open /var/log/vsay/sync-request: permission denied" on every press.
func TestAskingNeedsNoPermissionOnTheDirectory(t *testing.T) {
	withTempStatusDir(t)

	if err := PrepareSyncRequest(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Dir(syncRequestPath())
	// Read and execute only: entries can be seen, nothing can be created or
	// removed. This is what /var/log/vsay looks like to a normal user.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("cannot restrict the directory here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := RequestSync(); err != nil {
		t.Fatalf("asking for a sync needed permission on the directory: %v", err)
	}
	if !TakeSyncRequest() {
		t.Error("the request was written but not seen")
	}
}

// The file the user writes into must actually be writable by them. A daemon's
// umask is usually 022, which turns an O_CREATE 0666 into 0644 — and the
// button then fails for exactly the person it exists for.
func TestThePreparedFileIsWritableByWhoeverPressesTheButton(t *testing.T) {
	withTempStatusDir(t)

	if err := PrepareSyncRequest(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(syncRequestPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o022 == 0 {
		t.Errorf("the request file is %v — the menu bar runs as the logged-in user "+
			"and could not write it", fi.Mode().Perm())
	}
}

// "The agent has not prepared this" and "you are not allowed" send somebody to
// completely different places, so they must not arrive as the same error.
func TestAnUnpreparedRequestSaysSo(t *testing.T) {
	withTempStatusDir(t)

	err := RequestSync()
	if err == nil {
		t.Fatal("asking succeeded with no file prepared")
	}
	if !errors.Is(err, ErrSyncUnavailable) {
		t.Errorf("got %v, want ErrSyncUnavailable — the menu bar shows this to "+
			"somebody who needs to know the agent is not running", err)
	}
}

// The case that actually failed on a real machine: nothing had prepared the
// file, and the directory belongs to root.
//
// Creating is what needs permission on the directory, so a RequestSync that
// still passes O_CREATE reports "permission denied" — which is what the user
// saw, and which says nothing about the real cause. Opening an existing file
// cannot fail that way, so the honest answer is available only if the create
// is gone.
func TestAnUnpreparedRequestInARootOwnedDirectoryIsNotAPermissionError(t *testing.T) {
	withTempStatusDir(t)

	dir := filepath.Dir(syncRequestPath())
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("cannot restrict the directory here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	err := RequestSync()
	if err == nil {
		t.Fatal("asking succeeded with no prepared file in a read-only directory")
	}
	if os.IsPermission(err) {
		t.Fatalf("got %v — this is the message the user saw, and it blames them "+
			"for something the agent did not set up", err)
	}
	if !errors.Is(err, ErrSyncUnavailable) {
		t.Errorf("got %v, want ErrSyncUnavailable", err)
	}
}

// The install request names a PATH, and that path is not an instruction. The
// agent looks it up among the installers it has already scanned and judged;
// a path it does not recognise is ignored.
//
// That distinction is the whole safety of letting an unprivileged process
// write this file: it can pick one of the agent's own approved installers, it
// cannot name an arbitrary file to be run as root.
func TestAnInstallRequestCarriesOnlyAPath(t *testing.T) {
	withTempStatusDir(t)

	if err := PrepareInstallRequest(); err != nil {
		t.Fatal(err)
	}
	if got := TakeInstallRequest(); got != "" {
		t.Errorf("an empty request file returned %q", got)
	}

	const want = "/Users/someone/Downloads/VSCode.pkg"
	if err := RequestInstall(want); err != nil {
		t.Fatal(err)
	}
	if got := TakeInstallRequest(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Consumed: a request that fired once must not fire on every tick after.
	if got := TakeInstallRequest(); got != "" {
		t.Errorf("the same request was taken twice, returning %q", got)
	}
}

// Same directory-permission story as the sync request: the menu bar runs as
// the logged-in user and /var/log/vsay belongs to root.
func TestAskingToInstallNeedsNoPermissionOnTheDirectory(t *testing.T) {
	withTempStatusDir(t)
	if err := PrepareInstallRequest(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Dir(installRequestPath())
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("cannot restrict the directory here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := RequestInstall("/Users/someone/Downloads/x.pkg"); err != nil {
		t.Fatalf("asking needed permission on the directory: %v", err)
	}
}

func TestAnUnpreparedInstallRequestSaysSo(t *testing.T) {
	withTempStatusDir(t)
	err := RequestInstall("/x.pkg")
	if err == nil {
		t.Fatal("asking succeeded with no file prepared")
	}
	if !errors.Is(err, ErrSyncUnavailable) {
		t.Errorf("got %v, want ErrSyncUnavailable", err)
	}
}
