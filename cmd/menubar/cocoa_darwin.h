// Interface between the Go and Objective-C halves of the menu bar item.
#ifndef WXT_COCOA_DARWIN_H
#define WXT_COCOA_DARWIN_H

void wxt_set_state(int connected, const char *title, const char *detail);
void wxt_run(double pollSeconds);
void wxt_show_text(const char *title, const char *body);
void wxt_stop(void);

#endif
