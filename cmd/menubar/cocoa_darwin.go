//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#include "cocoa_darwin.h"
*/
import "C"

import "unsafe"

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

	C.wxt_software_begin()
	for i, it := range items {
		cTitle := C.CString(it.title)
		cDetail := C.CString(it.detail)
		// Clickable where the click does something: installing approved
		// software, or asking about software that is not approved.
		enabled := C.int(0)
		if it.clickable() {
			enabled = 1
		}
		C.wxt_software_add(cTitle, cDetail, enabled, C.int(i))
		C.free(unsafe.Pointer(cTitle))
		C.free(unsafe.Pointer(cDetail))
	}
	C.wxt_software_end(C.int(len(items)))

	// After the menu is rebuilt, not before: if somebody says no to the
	// dialog, the row is already there for them to come back to.
	askAboutNewInstalls(items)
}

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
