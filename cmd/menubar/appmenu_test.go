package main

import (
	"strings"
	"testing"
)

// The same application must appear once, with everything it offers.
//
// The agent publishes one row per THING it knows about: a mounted disk image
// is one, the installed copy of the same application is another. Shown flat,
// the same application appeared twice — once to install, once to remove —
// with nothing saying they were the same thing.
func TestOneApplicationIsOneEntryWhateverItOffers(t *testing.T) {
	apps := groupForMenu([]softwareRow{
		{name: "Visual Studio Code", title: "Visual Studio Code — update", detail: "Allowed by a rule. 1.95 → 1.96.",
			installable: true, updates: true},
		{name: "Visual Studio Code", title: "Visual Studio Code — remove", detail: "This Mac will move it to your Trash.",
			installed: true, removable: true},
	})

	if len(apps) != 1 {
		t.Fatalf("the same application produced %d entries", len(apps))
	}
	if apps[0].name != "Visual Studio Code" {
		t.Errorf("entry is named %q", apps[0].name)
	}
	if len(apps[0].actions) != 2 {
		t.Fatalf("it offers %d actions, wanted update and remove", len(apps[0].actions))
	}
	if apps[0].actions[0].label != "Update" || apps[0].actions[1].label != "Remove" {
		t.Errorf("actions are %q and %q", apps[0].actions[0].label, apps[0].actions[1].label)
	}
	// Each action still points at exactly one published row.
	if apps[0].actions[0].index != 0 || apps[0].actions[1].index != 1 {
		t.Error("an action no longer points at the row it came from, so clicking " +
			"it would act on something else")
	}
}

// The explanation belongs inside, under the name — not at the top level,
// where fifty applications became a hundred lines of prose.
func TestTheExplanationIsCarriedButNotAsAnEntry(t *testing.T) {
	apps := groupForMenu([]softwareRow{
		{name: "Claude", title: "Claude — needs approval", detail: "Your organisation does not allow Claude.",
			requestable: true},
	})

	if len(apps) != 1 {
		t.Fatalf("%d entries", len(apps))
	}
	if apps[0].note == "" {
		t.Error("the reason was dropped, so somebody who opens the submenu is " +
			"told what they can do and never why")
	}
	if apps[0].name != "Claude" {
		t.Errorf("the entry is named %q — the status belongs on the action", apps[0].name)
	}
}

// What is offered follows the state, and a statement is not a choice.
func TestWhatIsOfferedFollowsTheState(t *testing.T) {
	for _, c := range []struct {
		row     softwareRow
		label   string
		enabled bool
	}{
		{softwareRow{installed: true, removable: true}, "Remove", true},
		{softwareRow{installable: true, updates: true}, "Update", true},
		{softwareRow{installable: true}, "Install", true},
		{softwareRow{requestable: true}, "Request approval", true},
		{softwareRow{requestable: true, requested: true}, "Approval requested", false},
		{softwareRow{}, "Cannot be verified", false},
	} {
		label, enabled := actionFor(c.row)
		if label != c.label || enabled != c.enabled {
			t.Errorf("got %q/%v, wanted %q/%v", label, enabled, c.label, c.enabled)
		}
	}
}

// Order follows the rows, so the image somebody just opened stays first.
func TestTheImageJustOpenedStaysFirst(t *testing.T) {
	apps := groupForMenu([]softwareRow{
		{name: "Claude", title: "Claude — needs approval", requestable: true},
		{name: "Slack", title: "Slack — remove", installed: true, removable: true},
	})
	if len(apps) != 2 || apps[0].name != "Claude" {
		t.Errorf("the first entry is %v", apps)
	}
}

// Software a policy RULE forbids says so, and says nothing about signatures.
//
// A blocked row is not requestable, and "not requestable" used to fall
// through to the unverified wording. That sent somebody whose organisation
// had deliberately forbidden an application off hunting for a signature
// problem that does not exist, while the thing they could actually act on —
// get the rule changed — was never said.
func TestBlockedSoftwareSaysItIsBlockedRatherThanUnverifiable(t *testing.T) {
	label, enabled := actionFor(softwareRow{
		name: "Claude", title: "Claude", blocked: true,
	})
	if enabled {
		t.Error("a blocked row was clickable; there is nothing it can do")
	}
	if strings.Contains(strings.ToLower(label), "verif") {
		t.Fatalf("a blocked application is described as unverifiable (%q) — the "+
			"signature is fine, the organisation said no", label)
	}
	if !strings.Contains(strings.ToLower(label), "block") {
		t.Errorf("a blocked application does not say it is blocked: %q", label)
	}
}

// And the two refusals stay different. An unsigned bundle is not blocked by
// anybody; telling somebody their organisation forbids it sends them to
// argue with an administrator who has never heard of the application.
func TestAnUnverifiableBundleIsNotCalledBlocked(t *testing.T) {
	label, _ := actionFor(softwareRow{name: "Thing", title: "Thing"})
	if strings.Contains(strings.ToLower(label), "block") {
		t.Errorf("an unverifiable bundle is described as blocked: %q", label)
	}
}

// While the agent is copying, the menu must not go on offering the copy.
//
// A row being installed is STILL installable — the policy has not changed —
// so every offer branch matches it. Without the stage tested first the menu
// said "Install" for the whole length of the copy, somebody looked again,
// saw the same offer, and clicked it a second time.
func TestWorkInProgressIsNotOfferedAgain(t *testing.T) {
	for _, c := range []struct {
		what string
		row  softwareRow
		want string
	}{
		{"installing", softwareRow{name: "Slack", installable: true, stage: stageInstalling}, "Installing"},
		{"updating", softwareRow{name: "Slack", installable: true, updates: true, stage: stageInstalling}, "Updating"},
		{"checking", softwareRow{name: "Slack", stage: stageChecking}, "Checking"},
	} {
		label, enabled := actionFor(c.row)
		if enabled {
			t.Errorf("%s: the row is still clickable, so it can be started twice", c.what)
		}
		if !strings.HasPrefix(label, c.want) {
			t.Errorf("%s: label is %q, want it to start with %q", c.what, label, c.want)
		}
	}
}

// Replacing a version somebody is using is an UPDATE, and a menu that says
// "Installing" about it reads as a second copy being added beside the first.
func TestReplacingAVersionSaysUpdatingNotInstalling(t *testing.T) {
	label, _ := actionFor(softwareRow{
		name: "Slack", installable: true, updates: true, stage: stageInstalling,
	})
	if strings.Contains(label, "Install") {
		t.Errorf("replacing an installed version is described as installing: %q", label)
	}
}

// A settled row is unaffected: the stage is empty and the ordinary offers
// still come through. Without this the two cases above could be satisfied by
// a switch that never offers anything at all.
func TestASettledRowStillOffersItsAction(t *testing.T) {
	if label, enabled := actionFor(softwareRow{name: "Slack", installable: true}); !enabled ||
		label != "Install" {
		t.Errorf("a settled installable row offers %q (enabled=%v), want Install", label, enabled)
	}
	if label, enabled := actionFor(softwareRow{
		name: "Slack", installable: true, updates: true,
	}); !enabled || label != "Update" {
		t.Errorf("a settled update row offers %q (enabled=%v), want Update", label, enabled)
	}
}
