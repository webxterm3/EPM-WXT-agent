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
void wxt_software_add(const char *title, const char *detail, int enabled, int tag);
void wxt_software_end(int count);
void wxt_show_text(const char *title, const char *body);

// A two-button question. Returns 1 when the first button is chosen.
//
// Separate from wxt_show_text because the answer matters: this is what asks
// somebody whether to raise an approval request, and a dialog with one button
// could only tell them something.
int wxt_confirm(const char *title, const char *body, const char *okTitle,
                const char *cancelTitle);
void wxt_stop(void);

#endif
