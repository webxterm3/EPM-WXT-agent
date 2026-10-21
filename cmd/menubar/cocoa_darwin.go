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

// runMenuBar installs the status item and runs the Cocoa event loop. It does
// not return.
func runMenuBar() { C.wxt_run(C.double(pollInterval.Seconds())) }
