// Objective-C half of the menu bar item.
//
// A real .m file, not a cgo preamble. An @implementation inside a preamble is
// compiled into more than one object file and the link fails on duplicate
// symbols — cgo compiles .m files in the package directory exactly once.
#import <Cocoa/Cocoa.h>
#include <stdlib.h>
#include "cocoa_darwin.h"

// The menu bar item.
//
// Drawn as a shield with a status badge rather than loaded from an image file,
// for the same reason the application icon is generated: a template image that
// has to ship alongside the binary is a thing that can fail to ship, and this
// one has to adapt to light and dark menu bars anyway.
//
// The shield is a template image, so macOS tints it for the menu bar's
// appearance automatically. The badge is NOT — a green tick that goes grey in
// dark mode would be the one part of this that must never be ambiguous.

// Implemented in Go and exported with //export; cgo generates the
// declarations into _cgo_export.h.
#include "_cgo_export.h"

@interface WxtMenuDelegate : NSObject
@property (strong) NSStatusItem *item;
@end

@implementation WxtMenuDelegate
- (void)logs:(id)sender        { wxtMenuLogs(); }
- (void)permissions:(id)sender { wxtMenuPermissions(); }
- (void)status:(id)sender      { wxtMenuStatus(); }
- (void)uninstall:(id)sender   { wxtMenuUninstall(); }
- (void)quit:(id)sender        { wxtMenuQuit(); }
- (void)tick:(NSTimer *)t      { wxtRefresh(); }
@end

static WxtMenuDelegate *g_delegate = nil;
static NSMenuItem *g_titleItem = nil;
static NSMenuItem *g_detailItem = nil;

// wxt_icon draws the shield, with a tick or a cross badge.
static NSImage *wxt_icon(int connected) {
	NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(18, 18)];
	[img lockFocus];

	// Shield outline, in the menu bar's own colour.
	NSBezierPath *shield = [NSBezierPath bezierPath];
	[shield moveToPoint:NSMakePoint(3.5, 12.5)];
	[shield lineToPoint:NSMakePoint(3.5, 6.0)];
	[shield curveToPoint:NSMakePoint(9.0, 1.5)
	       controlPoint1:NSMakePoint(3.5, 3.5)
	       controlPoint2:NSMakePoint(6.0, 2.0)];
	[shield curveToPoint:NSMakePoint(14.5, 6.0)
	       controlPoint1:NSMakePoint(12.0, 2.0)
	       controlPoint2:NSMakePoint(14.5, 3.5)];
	[shield lineToPoint:NSMakePoint(14.5, 12.5)];
	[shield closePath];
	[[NSColor blackColor] setStroke];
	shield.lineWidth = 1.4;
	[shield stroke];

	[img unlockFocus];
	// Template: macOS recolours it for a light or dark menu bar, so it is
	// never the wrong colour against the background it lands on.
	img.template = YES;

	// The badge sits on a NON-template image on top, so its colour survives.
	NSImage *out = [[NSImage alloc] initWithSize:NSMakeSize(18, 18)];
	[out lockFocus];
	[img drawInRect:NSMakeRect(0, 0, 18, 18)];

	NSBezierPath *badge = [NSBezierPath bezierPath];
	if (connected) {
		[[NSColor systemGreenColor] setStroke];
		[badge moveToPoint:NSMakePoint(5.5, 7.5)];
		[badge lineToPoint:NSMakePoint(8.0, 5.2)];
		[badge lineToPoint:NSMakePoint(12.5, 10.5)];
	} else {
		[[NSColor systemRedColor] setStroke];
		[badge moveToPoint:NSMakePoint(6.0, 10.5)];
		[badge lineToPoint:NSMakePoint(12.0, 5.0)];
		[badge moveToPoint:NSMakePoint(12.0, 10.5)];
		[badge lineToPoint:NSMakePoint(6.0, 5.0)];
	}
	badge.lineWidth = 2.0;
	badge.lineCapStyle = NSLineCapStyleRound;
	badge.lineJoinStyle = NSLineJoinStyleRound;
	[badge stroke];
	[out unlockFocus];

	return out;
}

void wxt_set_state(int connected, const char *title, const char *detail) {
	if (!g_delegate) return;
	g_delegate.item.button.image = wxt_icon(connected);
	g_delegate.item.button.toolTip = [NSString stringWithUTF8String:title];
	g_titleItem.title = [NSString stringWithUTF8String:title];
	g_detailItem.title = [NSString stringWithUTF8String:detail];
}

void wxt_run(double pollSeconds) {
	@autoreleasepool {
		NSApplication *app = [NSApplication sharedApplication];
		// Accessory: a menu bar item, with no Dock icon and no window.
		[app setActivationPolicy:NSApplicationActivationPolicyAccessory];

		g_delegate = [[WxtMenuDelegate alloc] init];
		g_delegate.item = [[NSStatusBar systemStatusBar]
			statusItemWithLength:NSSquareStatusItemLength];

		NSMenu *menu = [[NSMenu alloc] init];

		// The first two rows are the answer to "is it working?", which is why
		// somebody clicks this at all. Disabled because they are a readout,
		// not something to pick.
		g_titleItem = [[NSMenuItem alloc] initWithTitle:@"wxt-agent" action:nil keyEquivalent:@""];
		g_titleItem.enabled = NO;
		[menu addItem:g_titleItem];

		g_detailItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
		g_detailItem.enabled = NO;
		[menu addItem:g_detailItem];

		[menu addItem:[NSMenuItem separatorItem]];

		NSMenuItem *st = [[NSMenuItem alloc] initWithTitle:@"Agent Status…"
			action:@selector(status:) keyEquivalent:@""];
		st.target = g_delegate;
		[menu addItem:st];

		NSMenuItem *pm = [[NSMenuItem alloc] initWithTitle:@"Check Permissions…"
			action:@selector(permissions:) keyEquivalent:@""];
		pm.target = g_delegate;
		[menu addItem:pm];

		NSMenuItem *lg = [[NSMenuItem alloc] initWithTitle:@"View Logs"
			action:@selector(logs:) keyEquivalent:@""];
		lg.target = g_delegate;
		[menu addItem:lg];

		NSMenuItem *un = [[NSMenuItem alloc] initWithTitle:@"Uninstall wxt-agent…"
			action:@selector(uninstall:) keyEquivalent:@""];
		un.target = g_delegate;
		[menu addItem:un];

		[menu addItem:[NSMenuItem separatorItem]];

		// Quits the MENU BAR ITEM, not the agent. Said in full, because
		// "Quit" next to a security agent's name reads as "switch off the
		// monitoring", which this cannot do — the agent is a root daemon and
		// keeps running.
		NSMenuItem *q = [[NSMenuItem alloc] initWithTitle:@"Hide Menu Bar Icon"
			action:@selector(quit:) keyEquivalent:@""];
		q.target = g_delegate;
		[menu addItem:q];

		g_delegate.item.menu = menu;

		wxtRefresh();
		[NSTimer scheduledTimerWithTimeInterval:pollSeconds
			target:g_delegate selector:@selector(tick:) userInfo:nil repeats:YES];

		[app run];
	}
}

// wxt_show_text puts a read-only, selectable block of text in a dialog.
void wxt_show_text(const char *title, const char *body) {
	@autoreleasepool {
		NSAlert *alert = [[NSAlert alloc] init];
		alert.messageText = [NSString stringWithUTF8String:title];
		[alert addButtonWithTitle:@"Close"];

		NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 460, 220)];
		scroll.hasVerticalScroller = YES;
		scroll.borderType = NSBezelBorder;

		NSTextView *text = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, 460, 220)];
		text.string = [NSString stringWithUTF8String:body];
		text.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
		// Read-only but SELECTABLE: the whole point of showing a diagnostic is
		// that somebody can copy it into a support message.
		text.editable = NO;
		text.selectable = YES;
		text.richText = NO;
		[text.textContainer setWidthTracksTextView:YES];
		scroll.documentView = text;

		alert.accessoryView = scroll;
		[NSApp activateIgnoringOtherApps:YES];
		[alert runModal];
	}
}

void wxt_stop(void) { [NSApp terminate:nil]; }
