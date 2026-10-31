//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#include "cocoa_darwin.h"
*/
import "C"

import (
	"time"
	"unsafe"
)

//export wxtMenuLogs
func wxtMenuLogs() { openLogs() }

//export wxtMenuPermissions
func wxtMenuPermissions() { checkPermissions() }

//export wxtMenuStatus
func wxtMenuStatus() { showStatus() }

//export wxtMenuUninstall
func wxtMenuUninstall() { uninstallAgent() }

//export wxtMenuQuit
func wxtMenuQuit() { C.wxt_stop() }

//export wxtMenuSync
func wxtMenuSync() { requestSync() }

//export wxtMenuInstall
func wxtMenuInstall(tag C.int) { requestApproval(int(tag)) }

//export wxtRefresh
func wxtRefresh() {
	connected, title, detail, sync := currentState()

	cTitle := C.CString(title)
	cDetail := C.CString(detail)
	cSync := C.CString(sync)
	defer func() {
		C.free(unsafe.Pointer(cTitle))
		C.free(unsafe.Pointer(cDetail))
		C.free(unsafe.Pointer(cSync))
	}()

	flag := C.int(0)
	if connected {
		flag = 1
	}
	C.wxt_set_state(flag, cTitle, cDetail, cSync)
	refreshSoftwareMenu()
}

// refreshSoftwareMenu rebuilds the list of downloaded installers.
//
// Rebuilt whole on every tick rather than diffed: the list changes whenever
// somebody downloads or deletes a file, and keeping a live NSMenu in step by
// index is the kind of bookkeeping that leaves a stale row pointing at a file
// that is no longer there.
func refreshSoftwareMenu() {
	items := pendingForThisUser()
	apps := groupForMenu(items)

	C.wxt_software_begin()
	for _, app := range apps {
		cName := C.CString(app.name)
		C.wxt_software_app(cName)
		C.free(unsafe.Pointer(cName))

		if app.note != "" {
			cNote := C.CString(app.note)
			C.wxt_software_note(cNote)
			C.free(unsafe.Pointer(cNote))
		}

		for _, a := range app.actions {
			cLabel := C.CString(a.label)
			enabled := C.int(0)
			if a.enabled {
				enabled = 1
			}
			C.wxt_software_action(cLabel, enabled, C.int(a.index))
			C.free(unsafe.Pointer(cLabel))
		}
	}
	// Counted in APPLICATIONS, not rows: the heading says how many things
	// there are to look at, and one application offering two actions is one
	// thing to look at.
	C.wxt_software_end(C.int(len(apps)))

	// Before the dialog, because the two share one panel and the dialog
	// takes it down.
	showCheckingPanel(items)

	// After the menu is rebuilt, not before: if somebody says no to the
	// dialog, the row is already there for them to come back to.
	askAboutNewInstalls(items)
}

// progressShow puts a floating panel on screen saying work is running.
func progressShow(title, body string) {
	cTitle := C.CString(title)
	cBody := C.CString(body)
	defer func() {
		C.free(unsafe.Pointer(cTitle))
		C.free(unsafe.Pointer(cBody))
	}()
	C.wxt_progress_show(cTitle, cBody)
}

func progressHide() { C.wxt_progress_hide() }

// progressUpdate moves the bar. A negative percent means "not measurable",
// which puts the bar back to sweeping rather than freezing it at zero.
func progressUpdate(percent float64, body string) {
	cBody := C.CString(body)
	defer C.free(unsafe.Pointer(cBody))
	C.wxt_progress_update(C.double(percent), cBody)
}

// pumpRunLoop waits WITHOUT freezing the interface.
//
// time.Sleep on this thread stops every pixel this process draws, because
// the menu bar's work happens on the main thread — so the progress bar put
// up a moment earlier would sit motionless for the whole install, saying the
// exact opposite of what it is there to say.
func pumpRunLoop(d time.Duration) { C.wxt_pump(C.double(d.Seconds())) }

// showText displays a read-only, selectable block of text.
func showText(title, body string) {
	cTitle := C.CString(title)
	cBody := C.CString(body)
	defer func() {
		C.free(unsafe.Pointer(cTitle))
		C.free(unsafe.Pointer(cBody))
	}()
	C.wxt_show_text(cTitle, cBody)
}

// confirmText asks a two-button question and reports whether the first
// button was chosen.
func confirmText(title, body, okTitle, cancelTitle string) bool {
	cTitle := C.CString(title)
	cBody := C.CString(body)
	cOK := C.CString(okTitle)
	cCancel := C.CString(cancelTitle)
	defer func() {
		C.free(unsafe.Pointer(cTitle))
		C.free(unsafe.Pointer(cBody))
		C.free(unsafe.Pointer(cOK))
		C.free(unsafe.Pointer(cCancel))
	}()
	return C.wxt_confirm(cTitle, cBody, cOK, cCancel) == 1
}

// runMenuBar installs the status item and runs the Cocoa event loop. It does
// not return.
func runMenuBar() { C.wxt_run(C.double(pollInterval.Seconds())) }
