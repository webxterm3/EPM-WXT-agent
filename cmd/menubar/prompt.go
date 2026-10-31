package main

// Asking at the moment it matters.
//
// A row in a menu is only seen by somebody who opens the menu. The person
// this feature is for is not doing that: they have just double-clicked a disk
// image, they are looking at a Finder window, and the next thing they do is
// drag the application across and meet a demand for an administrator password
// they do not have. By the time they go looking in the menu bar they have
// already concluded the machine is broken.
//
// So the question is put in front of them instead, when the volume appears.

// installPrompts decides which mounted application — if any — to ask about,
// and remembers what it has already asked.
type installPrompts struct {
	asked map[string]bool
}

func newInstallPrompts() *installPrompts {
	return &installPrompts{asked: map[string]bool{}}
}

// next picks at most one row to ask about.
//
// At most ONE, even when several volumes appear together: dialogs are modal,
// and three stacked on top of each other is not three questions, it is a
// machine that has stopped responding.
//
// Paths that are no longer in the list are forgotten. That is what makes
// ejecting and re-opening a disk image ask again — which is the one gesture
// somebody who dismissed the question will naturally reach for, and it would
// be unhelpful if the second attempt were silent.
func (p *installPrompts) next(rows []softwareRow) (softwareRow, bool) {
	present := make(map[string]bool, len(rows))
	for _, r := range rows {
		present[r.path] = true
	}
	for path := range p.asked {
		if !present[path] {
			delete(p.asked, path)
		}
	}

	for _, r := range rows {
		// Only about a disk image somebody has just opened.
		//
		// NOT about software already installed. Those rows are clickable
		// too — clicking one removes it — but nobody opened anything, so
		// there is no moment to interrupt and nothing they have to decide.
		// Without this they were picked like any other clickable row and
		// shown the approval dialog, which then read "Visual Studio Code
		// needs approval" above "this Mac will move Visual Studio Code to
		// your Trash": the title from one branch, the detail from another,
		// about an application that was already installed and allowed.
		//
		// Worse, the prompt offers ONE row per tick, so a Mac with a few
		// removable applications spent every tick on them and the image the
		// person had actually just opened was never asked about at all.
		if r.installed {
			continue
		}

		// Where clicking does something — installing approved software, or
		// asking about software nobody has ruled on — OR where there is
		// something they have to be TOLD.
		//
		// Blocked is the second kind. Nothing is offered and nothing is
		// decided, but the agent no longer raises a request for it, and
		// somebody who has just opened a disk image is owed the reason
		// there and then. Left out of this list they would watch the image
		// close itself and conclude the Mac was broken — which is the exact
		// failure this whole file exists to prevent.
		//
		// An unverified bundle is still left out: nothing can change that
		// answer and there is nothing to do about it at the Mac.
		if !r.clickable() && !r.blocked {
			continue
		}
		if r.path == "" || p.asked[r.path] {
			continue
		}
		// An ask that has already gone out is still worth SAYING once.
		//
		// This used to skip those rows entirely, from when the request was
		// raised by the person clicking. It is now raised automatically the
		// moment the image is opened — so by the time the menu bar looks,
		// every refused row already says "requested", every one was
		// skipped, and the person saw nothing at all: their disk image
		// simply closed itself.
		//
		// Saying it once is handled below, by `asked`, and that entry
		// survives the image being ejected because the agent goes on
		// publishing a closed image for fifteen minutes. So they are told
		// once per attempt, not once per mount and not never.
		p.asked[r.path] = true
		return r, true
	}
	return softwareRow{}, false
}
