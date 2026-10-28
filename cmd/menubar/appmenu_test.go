package main

import "testing"

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
