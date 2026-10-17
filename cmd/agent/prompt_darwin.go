//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// wxt_prompt_enrolment shows a dialog with a REAL multi-line text area and
// returns what was typed, or NULL if cancelled.
//
// AppleScript's `display dialog … default answer` is the usual way to ask for
// a line of text, and it is the reason this exists: its field is a single
// line. An enrolment command is far longer than that field is wide, so only
// the tail was ever visible — somebody could not see what they had pasted,
// could not check it was complete, and editing it was miserable.
//
// An NSTextView in an NSAlert accessory is the smallest thing that is
// genuinely a text area: it wraps, it scrolls, and the whole command is in
// front of the person before they press Install.
//
// The caller frees the returned string.
// wxt_alert_icon loads the product icon that belongs beside the running
// binary, so the dialog is marked with the product rather than with the
// generic executable glyph macOS gives an unbundled command-line tool. That
// glyph is what made this dialog look like a stray folder asking for a
// password.
static NSImage *wxt_alert_icon(void) {
	NSString *exe = [[NSBundle mainBundle] executablePath];
	if (!exe) {
		exe = [[[NSProcessInfo processInfo] arguments] firstObject];
	}
	if (!exe) return nil;

	// The icon ships next to the binary inside Contents/Resources, which is
	// where the installer app runs from.
	// The executables live in Contents/MacOS and the icon in
	// Contents/Resources, so the first candidate steps up and across. The
	// beside-the-binary case is kept for a build run straight out of dist/.
	NSString *dir = [exe stringByDeletingLastPathComponent];
	NSArray *candidates = @[
		[[dir stringByDeletingLastPathComponent]
			stringByAppendingPathComponent:@"Resources/wxt-agent.icns"],
		[dir stringByAppendingPathComponent:@"wxt-agent.icns"],
		@"/Applications/wxt-agent.app/Contents/Resources/wxt-agent.icns",
	];
	for (NSString *path in candidates) {
		if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
			NSImage *img = [[NSImage alloc] initWithContentsOfFile:path];
			if (img) return img;
		}
	}
	return nil;
}

char *wxt_prompt_enrolment(const char *title, const char *message, const char *prefill) {
	// Called ON the main thread, directly — no dispatch to the main queue.
	//
	// A Go program does not run a Cocoa run loop, so the main queue is never
	// serviced: dispatching to it and waiting traps the process. The Go side
	// pins itself to the main OS thread instead (runtime.LockOSThread) and
	// calls straight in.
	@autoreleasepool {
		NSApplication *app = [NSApplication sharedApplication];
		// Accessory, not Regular: this puts up one dialog and exits, and a
		// Dock icon appearing for it would be noise.
		[app setActivationPolicy:NSApplicationActivationPolicyAccessory];
		[app activateIgnoringOtherApps:YES];

		NSAlert *alert = [[NSAlert alloc] init];
		alert.messageText = [NSString stringWithUTF8String:title];
		alert.informativeText = [NSString stringWithUTF8String:message];
		NSImage *icon = wxt_alert_icon();
		if (icon) alert.icon = icon;
		[alert addButtonWithTitle:@"Install"];
		NSButton *cancel = [alert addButtonWithTitle:@"Cancel"];
		// Escape is given to Cancel explicitly. NSAlert normally does this for
		// the second button, but the text view below takes first responder and
		// swallows the key — leaving a dialog that can only be dismissed with
		// the mouse.
		cancel.keyEquivalent = @"\033";

		// An accessory stack: the field, then a quiet line of help under it.
		//
		// The help belongs below the field rather than in informativeText
		// because it describes what to do with the field, and above it the
		// eye reaches the text area first and never comes back.
		const CGFloat width = 540;
		const CGFloat fieldHeight = 104;
		const CGFloat hintHeight = 34;
		const CGFloat gap = 8;

		NSView *stack = [[NSView alloc] initWithFrame:
			NSMakeRect(0, 0, width, fieldHeight + gap + hintHeight)];

		// Scrollable so a long command is reachable, and tall enough that a
		// typical one is fully visible without scrolling at all.
		NSScrollView *scroll = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(0, hintHeight + gap, width, fieldHeight)];
		scroll.hasVerticalScroller = YES;
		scroll.borderType = NSBezelBorder;
		scroll.drawsBackground = YES;

		NSTextField *hint = [[NSTextField alloc] initWithFrame:
			NSMakeRect(2, 0, width - 4, hintHeight)];
		hint.stringValue = @"It starts with “sudo wxt-agent configure” and contains a long "
		                    "enrolment token.\nYour Mac will ask for your password next.";
		hint.font = [NSFont systemFontOfSize:11];
		hint.textColor = [NSColor secondaryLabelColor];
		hint.bezeled = NO;
		hint.editable = NO;
		hint.selectable = NO;
		hint.drawsBackground = NO;
		// An NSTextField is single-line by default, so a string with a newline
		// in it renders as one clipped line. Both of these are needed for the
		// second line to exist at all.
		hint.usesSingleLineMode = NO;
		hint.cell.wraps = YES;
		hint.maximumNumberOfLines = 2;

		[stack addSubview:scroll];
		[stack addSubview:hint];

		NSTextView *text = [[NSTextView alloc]
			initWithFrame:NSMakeRect(0, 0, width, fieldHeight)];
		text.string = [NSString stringWithUTF8String:prefill];
		text.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
		text.textContainerInset = NSMakeSize(4, 6);
		// Every one of these would corrupt the command: smart quotes replace
		// the plain ones around each value, and the dash substitution turns
		// "--token" into an en-dash.
		text.automaticQuoteSubstitutionEnabled = NO;
		text.automaticDashSubstitutionEnabled = NO;
		text.automaticTextReplacementEnabled = NO;
		text.automaticSpellingCorrectionEnabled = NO;
		text.richText = NO;
		text.horizontallyResizable = NO;
		[text.textContainer setWidthTracksTextView:YES];
		scroll.documentView = text;

		alert.accessoryView = stack;
		[alert.window setInitialFirstResponder:text];
		// Selected, not just focused: the field is prefilled from the
		// clipboard, and the usual next move is to replace it wholesale with
		// a different command rather than edit the one that is there.
		[text setSelectedRange:NSMakeRange(0, [text.string length])];

		NSModalResponse r = [alert runModal];
		if (r != NSAlertFirstButtonReturn) {
			return NULL;
		}
		return strdup([text.string UTF8String]);
	}
}
*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/spf13/cobra"
)

// Cocoa insists on the main thread, and a Go program does not run a Cocoa run
// loop — so dispatching to the main queue and waiting traps the process. This
// pins the main goroutine to the main OS thread so the dialog can be called
// straight from it.
func init() { runtime.LockOSThread() }

// newPromptCommand asks for the enrolment command in a real text area and
// prints what was entered.
//
// A separate command rather than part of the installer script because the
// script is shell and this is Cocoa: the app bundle shells out to it and reads
// the result. Hidden, because it is machinery, not something to run by hand.
func newPromptCommand() *cobra.Command {
	c := &cobra.Command{
		Use:    "prompt-enrolment",
		Short:  "Ask for the enrolment command in a dialog (used by the macOS app)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			prefill, _ := cmd.Flags().GetString("prefill")

			title := C.CString("Enrol this Mac with EPM")
			msg := C.CString("Paste the enrolment command from the EPM portal. " +
				"If you pressed Copy there, it is already filled in below.")
			pre := C.CString(prefill)
			defer func() {
				C.free(unsafe.Pointer(title))
				C.free(unsafe.Pointer(msg))
				C.free(unsafe.Pointer(pre))
			}()

			out := C.wxt_prompt_enrolment(title, msg, pre)
			if out == nil {
				// Cancelled. Exit 1 so the caller can tell it apart from an
				// empty answer, which is a different mistake.
				os.Exit(1)
			}
			defer C.free(unsafe.Pointer(out))

			fmt.Print(C.GoString(out))
			return nil
		},
	}
	c.Flags().String("prefill", "", "text to start the field with")
	return c
}
