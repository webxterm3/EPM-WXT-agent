package main

import "testing"

func blockedRow(path string) softwareRow {
	return softwareRow{title: path + " — blocked", path: path, requestable: true}
}

func TestSomebodyIsAskedOnceNotEveryFiveSeconds(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{blockedRow("/Volumes/Zoom")}

	if _, ok := p.next(rows); !ok {
		t.Fatal("nobody was asked about a blocked application that just appeared")
	}
	// The menu refreshes on a timer. Asking again on the next tick would put
	// a modal dialog on the screen every few seconds.
	for i := 0; i < 5; i++ {
		if row, ok := p.next(rows); ok {
			t.Fatalf("asked again about %s on tick %d", row.path, i+2)
		}
	}
}

func TestOpeningTheImageAgainAsksAgain(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{blockedRow("/Volumes/Zoom")}
	p.next(rows)

	// Ejected.
	if _, ok := p.next(nil); ok {
		t.Fatal("asked about a volume that is not mounted")
	}
	// Opened again — a deliberate second attempt, which must not be silent.
	if _, ok := p.next(rows); !ok {
		t.Fatal("somebody re-opened the disk image and was told nothing")
	}
}

func TestThreeVolumesAreAskedOneAtATime(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{
		blockedRow("/Volumes/One"),
		blockedRow("/Volumes/Two"),
		blockedRow("/Volumes/Three"),
	}

	// One per call, and the caller calls once per refresh — so the three
	// questions are asked in turn rather than three modal dialogs landing on
	// top of each other, which is not three questions but a frozen machine.
	var asked []string
	for i := 0; i < 3; i++ {
		row, ok := p.next(rows)
		if !ok {
			t.Fatalf("only %d of 3 volumes were ever asked about", i)
		}
		asked = append(asked, row.path)
	}
	if row, ok := p.next(rows); ok {
		t.Fatalf("asked about %s a second time", row.path)
	}

	seen := map[string]bool{}
	for _, path := range asked {
		if seen[path] {
			t.Fatalf("%s was asked about twice while another volume was never asked about", path)
		}
		seen[path] = true
	}
}

// An unverified bundle is the one case with nothing to offer: approval
// cannot fix a signature, and installing it is exactly what must not happen.
func TestNobodyIsInterruptedAboutABundleNothingCanBeDoneWith(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{{title: "Unsigned thing", path: "/Volumes/Odd"}}

	if row, ok := p.next(rows); ok {
		t.Fatalf("interrupted somebody about %s, which no answer can help", row.path)
	}
}

// Approved software IS offered, because somebody has to say install.
//
// It used to be passed over on the grounds that the person could simply drag
// it across. They cannot: the window that drag needs is an access-control
// entry on /Applications, and a managed Mac refuses to write one even for
// root. Without this prompt, approved software sits in an open disk image
// with no way to install it that does not ask for a password.
func TestApprovedSoftwareIsOfferedForInstalling(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{
		{title: "Slack — approved, click to install", path: "/Volumes/Slack", installable: true},
	}

	row, ok := p.next(rows)
	if !ok {
		t.Fatal("approved software was never offered, so nothing installs it")
	}
	if !row.installable {
		t.Errorf("offered %q as something to ask about rather than to install", row.title)
	}
}

// An ask that has already gone out is still said once.
//
// The request is raised automatically the moment the image is opened, so by
// the time the menu bar looks, every refused row already says "requested".
// Skipping those meant the person saw nothing at all — their disk image
// simply closed itself, with no dialog and no explanation.
func TestSomebodyIsToldEvenWhenTheAskWentOutByItself(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{{
		title: "Claude — approval requested", path: "/Volumes/Claude",
		requestable: true, requested: true,
	}}

	if _, ok := p.next(rows); !ok {
		t.Fatal("nothing was said about an image that closed itself, so the " +
			"person is left with a disk image that vanished and no reason")
	}
	// Once, though. The agent goes on publishing a closed image for fifteen
	// minutes, and a dialog on every tick is not an explanation.
	for i := 0; i < 5; i++ {
		if row, ok := p.next(rows); ok {
			t.Fatalf("said it again about %s on tick %d", row.path, i+2)
		}
	}
}

// But one that has NOT been asked for yet is still offered — otherwise
// somebody whose request never left the machine has no way to try.
func TestAnUnrequestedApplicationIsStillAskedAbout(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{{
		title: "Claude — needs approval", path: "/Volumes/Claude",
		requestable: true, requested: false,
	}}

	if _, ok := p.next(rows); !ok {
		t.Error("software nobody has asked about yet is never offered, so there " +
			"is no way to raise the request at all")
	}
}

// Nobody is interrupted about software they already have.
//
// Installed rows are clickable — clicking one removes it — but nobody opened
// anything, so there is no moment to interrupt. Offered like any other
// clickable row, they were shown the APPROVAL dialog: the title from one
// branch above the detail from another, reading "Visual Studio Code needs
// approval" over "this Mac will move Visual Studio Code to your Trash",
// about an application that was installed and allowed.
func TestNobodyIsInterruptedAboutSoftwareTheyAlreadyHave(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{{
		title: "Visual Studio Code — remove", path: "/Applications/Visual Studio Code.app",
		installed: true, removable: true,
	}}

	if row, ok := p.next(rows); ok {
		t.Fatalf("interrupted somebody about %s, which is already installed", row.path)
	}
}

// And installed rows must not crowd out the image somebody just opened.
//
// One row is offered per tick. With a few removable applications in the
// list, every tick was spent on those and the disk image the person had
// actually just opened was never asked about at all.
func TestAnOpenedImageIsAskedAboutDespiteInstalledSoftware(t *testing.T) {
	p := newInstallPrompts()
	rows := []softwareRow{
		{title: "Slack — remove", path: "/Applications/Slack.app", installed: true, removable: true},
		{title: "VS Code — remove", path: "/Applications/VS Code.app", installed: true, removable: true},
		{title: "Claude — needs approval", path: "/Volumes/Claude", requestable: true},
	}

	row, ok := p.next(rows)
	if !ok {
		t.Fatal("the image somebody just opened was never asked about")
	}
	if row.path != "/Volumes/Claude" {
		t.Errorf("asked about %s instead of the image that was just opened", row.path)
	}
}
