// Interface between the Go and Objective-C halves of the menu bar item.
#ifndef WXT_COCOA_DARWIN_H
#define WXT_COCOA_DARWIN_H

void wxt_set_state(int connected, const char *title, const char *detail, const char *sync);
void wxt_run(double pollSeconds);

// The "Software" submenu, rebuilt from scratch on every refresh.
//
// Rebuilt rather than spliced into the main menu: the list changes whenever
// somebody downloads or deletes something, and removing the right range of
// items from a live NSMenu by index is the kind of bookkeeping that goes
// wrong silently. Replacing a whole submenu cannot leave a stale row behind.
void wxt_software_begin(void);

// One application, which opens a submenu of what can be done with it.
//
// Two levels rather than one: the flat list put every application's state
// underneath it in grey, so a Mac with fifty managed applications was a
// hundred rows of prose. The name is what somebody is looking for; what can
// be done with it is what they want once they have found it.
void wxt_software_app(const char *name);

// One action inside the current application's submenu. An action with
// enabled == 0 is a statement rather than a choice — "approval requested",
// "cannot be verified" — and carries no tag worth clicking.
void wxt_software_action(const char *label, int enabled, int tag);

// A line of explanation inside the current application's submenu, shown
// above its actions. Never at the top level.
void wxt_software_note(const char *text);

void wxt_software_end(int count);
void wxt_show_text(const char *title, const char *body);

// A two-button question. Returns 1 when the first button is chosen.
//
// Separate from wxt_show_text because the answer matters: this is what asks
// somebody whether to raise an approval request, and a dialog with one button
// could only tell them something.
int wxt_confirm(const char *title, const char *body, const char *okTitle,
                const char *cancelTitle);
// A floating panel saying that something is running, with an indeterminate
// bar. Shown DURING an operation, which is why it is a panel and not an
// alert: an alert is modal and would have to be dismissed before the work
// could start. Calling show again replaces the text on the panel already up.
void wxt_progress_show(const char *title, const char *body);
void wxt_progress_hide(void);

// Move the bar. A percent below zero puts it back to indeterminate, which is
// what honest ignorance looks like — a bar frozen at 0% reads as stuck.
// A NULL body leaves the text alone.
void wxt_progress_update(double percent, const char *body);

// Drain events for a moment instead of sleeping.
//
// The menu bar runs on the main thread. A Go function that sleeps while it
// waits for the agent freezes everything this process draws — including the
// progress bar it just put on screen.
void wxt_pump(double seconds);

void wxt_stop(void);

#endif
