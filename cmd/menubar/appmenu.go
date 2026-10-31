package main

import "github.com/Yesveer/wxt-agent/internal/agentstatus"

// Grouping the menu by application rather than by row.
//
// The agent publishes one row per THING it knows about: a mounted disk image
// is one, the installed copy of the same application is another. Shown flat,
// with each row's reason underneath it in grey, a Mac with fifty managed
// applications was a hundred lines of prose — and the same application
// appeared twice, once to install and once to remove, with nothing saying
// they were the same thing.
//
// What somebody is looking for is the application. What they want once they
// have found it is what can be done with it. So the name is the row, the
// actions are its submenu, and the explanation goes inside, where it is read
// by somebody who has already chosen what they are looking at.

// appMenu is one application and everything offered for it.
type appMenu struct {
	name string
	// note explains the policy position, shown above the actions.
	note    string
	actions []appAction
}

// The stages the agent publishes. Mirrored from agentstatus rather than
// imported as strings at each use, so a typo is a compile error here rather
// than a row that silently never matches.
const (
	stageChecking   = agentstatus.StageChecking
	stageInstalling = agentstatus.StageInstalling
)

// appAction is one line inside an application's submenu. index points back
// into the published rows, so a click still means exactly one of them.
type appAction struct {
	label   string
	enabled bool
	index   int
}

// actionFor names what this row offers, and whether it is a choice or a
// statement.
func actionFor(r softwareRow) (label string, enabled bool) {
	switch {
	// Work in progress comes FIRST, before any of the offers.
	//
	// Not last, and not folded into them. While the agent is copying, the
	// row is still installable and `installable` is still true — so every
	// branch below would go on offering "Install" for the whole length of
	// the copy, which is exactly what made somebody click it twice.
	case r.stage == stageInstalling:
		// "Updating" where there is something to replace. Somebody watching
		// their existing copy be swapped out should see that word and not
		// one that suggests a second copy is being added.
		if r.updates {
			return "Updating…", false
		}
		return "Installing…", false

	case r.stage == stageChecking:
		// The image is mounted and the answer is not settled. Deliberately
		// a few seconds: the agent will not judge a half-mounted bundle.
		// Saying so is the difference between a Mac that is working on it
		// and a Mac that ignored the double-click.
		return "Checking…", false

	case r.installed && r.removable:
		return "Remove", true
	case r.installable && r.updates:
		return "Update", true
	case r.installable:
		return "Install", true
	case r.requestable && r.requested:
		// A statement: the request is in somebody's queue and there is
		// nothing here to decide.
		return "Approval requested", false
	case r.requestable:
		return "Request approval", true
	case r.blocked:
		// A statement, and the end of the road.
		//
		// No approval route, because a rule has already answered this for
		// the whole organisation and the portal will not let anybody
		// overturn it from here. The note above the actions says what to do
		// instead, which is to get the rule changed.
		return "Blocked by your organisation", false
	default:
		// Unverified. Not offered an approval route either, but for an
		// entirely different reason: the signature is what is missing, and
		// no approval supplies one.
		return "Cannot be verified", false
	}
}

// groupForMenu turns published rows into one entry per application.
//
// Order is preserved from the rows, so whatever the agent considers most
// relevant — the image somebody just opened — stays at the top.
func groupForMenu(rows []softwareRow) []appMenu {
	var out []appMenu
	at := map[string]int{}

	for i, r := range rows {
		name := appNameOf(r)
		if name == "" {
			continue
		}

		label, enabled := actionFor(r)
		action := appAction{label: label, enabled: enabled, index: i}

		if pos, seen := at[name]; seen {
			out[pos].actions = append(out[pos].actions, action)
			// The first row to carry a reason keeps it. A mounted image
			// explains the policy position; the installed copy repeats it.
			if out[pos].note == "" {
				out[pos].note = r.detail
			}
			continue
		}

		at[name] = len(out)
		out = append(out, appMenu{name: name, note: r.detail, actions: []appAction{action}})
	}
	return out
}
