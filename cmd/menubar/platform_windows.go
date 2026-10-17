//go:build windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The notification-area icon, built on Shell_NotifyIcon.
//
// Plain syscalls rather than cgo, the same way the Windows session helper is
// written: user32 and shell32 are all this needs, and keeping the Windows
// build cgo-free means it cross-compiles from anywhere.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procLoadImage        = user32.NewProc("LoadImageW")
	procDestroyIcon      = user32.NewProc("DestroyIcon")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procSetTimer         = user32.NewProc("SetTimer")
	procMessageBox       = user32.NewProc("MessageBoxW")

	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")

	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy  = 0x0002
	wmCommand  = 0x0111
	wmTimer    = 0x0113
	wmTrayIcon = 0x0400 + 1 // WM_APP + 1

	wmRButtonUp = 0x0205
	wmLButtonUp = 0x0202

	nimAdd    = 0x0000
	nimModify = 0x0001
	nimDelete = 0x0002

	nifMessage = 0x0001
	nifIcon    = 0x0002
	nifTip     = 0x0004

	imageIcon      = 1
	lrLoadFromFile = 0x0010
	lrDefaultSize  = 0x0040
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
	mfString       = 0x0000
	mfSeparator    = 0x0800
	mfGrayed       = 0x0001
	timerID        = 1
	mbOK           = 0x0000
	mbYesNo        = 0x0004
	mbIconInfo     = 0x0040
	mbIconWarning  = 0x0030
	// What MessageBox returns for the Yes button.
	idYes = 6
)

// Menu command identifiers. Deliberately not 0: TrackPopupMenu returns 0 when
// nothing was chosen, so a menu item with that id is indistinguishable from a
// dismissed menu.
const (
	cmdStatus      = 1
	cmdPermissions = 2
	cmdLogs        = 3
	cmdUninstall   = 4
	cmdHide        = 5
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

// The window exists only to receive messages: the notification area delivers
// clicks to a window procedure, and a timer needs one too. It is never shown.
var (
	hwnd      windows.Handle
	iconOK    windows.Handle
	iconBad   windows.Handle
	lastTip   string
	lastState bool
	haveState bool
	// Beside the agent, which configure installs to C:\ProgramData\vsay.
	// Not Program Files: the agent is not installed there either, and two
	// locations is one more than has to be kept in step.
	installDir = `C:\ProgramData\vsay`
)

// agentPath is the installed agent, which this program shells out to rather
// than reimplementing. "Check permissions" here and the same command in a
// terminal must not be two different checks.
var agentPath = filepath.Join(installDir, "wxt-agent.exe")

// openLogs shows the agent log in Notepad, which is on every Windows machine
// and needs nothing installed.
func openLogs() {
	_ = exec.Command("notepad.exe", filepath.Join(installDir, "logs", "agent.log")).Start()
}

func init() {
	// The message loop and the window must live on one thread.
	runtime.LockOSThread()
}

func run() {
	className, _ := windows.UTF16PtrFromString("WxtAgentTray")
	inst, _, _ := procGetModuleHandle.Call(0)

	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   windows.NewCallback(wndProc),
		Instance:  windows.Handle(inst),
		ClassName: className,
	}
	if atom, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		fatal("could not register the tray window class", err)
		return
	}

	h, _, err := procCreateWindowEx.Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)),
		0, 0, 0, 0, 0, 0, 0, uintptr(inst), 0)
	if h == 0 {
		fatal("could not create the tray window", err)
		return
	}
	hwnd = windows.Handle(h)

	iconOK = loadIcon("wxt-agent-connected.ico")
	iconBad = loadIcon("wxt-agent-disconnected.ico")

	addIcon()
	refresh()

	procSetTimer.Call(uintptr(hwnd), timerID, uintptr(pollInterval.Milliseconds()), 0)

	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// loadIcon reads one of the two state icons from beside the executable.
//
// From a file rather than an embedded resource because a Go binary carries no
// icon resource without a .syso, and shipping two .ico files beside the
// executable is simpler than generating one.
func loadIcon(name string) windows.Handle {
	path := filepath.Join(installDir, name)
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	h, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(p)),
		imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
	return windows.Handle(h)
}

func notifyData(flags uint32) notifyIconData {
	return notifyIconData{
		CbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:             hwnd,
		UID:              1,
		UFlags:           flags,
		UCallbackMessage: wmTrayIcon,
	}
}

func addIcon() {
	d := notifyData(nifMessage | nifIcon | nifTip)
	d.HIcon = iconBad
	copyTip(&d, "wxt-agent")
	procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&d)))
}

func copyTip(d *notifyIconData, s string) {
	u := windows.StringToUTF16(s)
	if len(u) > len(d.SzTip) {
		u = u[:len(d.SzTip)-1]
		u = append(u, 0)
	}
	copy(d.SzTip[:], u)
}

// refresh re-reads the published status and updates the icon and tooltip.
//
// Only when something changed: Shell_NotifyIcon on every tick makes the icon
// flicker on some Windows versions, and there is nothing to gain from
// repainting an unchanged picture.
func refresh() {
	connected, title, detail := currentState()
	tip := title
	if detail != "" {
		tip = title + "\n" + detail
	}

	if haveState && connected == lastState && tip == lastTip {
		return
	}
	lastState, lastTip, haveState = connected, tip, true

	d := notifyData(nifIcon | nifTip)
	if connected {
		d.HIcon = iconOK
	} else {
		d.HIcon = iconBad
	}
	copyTip(&d, tip)
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

func removeIcon() {
	d := notifyData(0)
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
	if iconOK != 0 {
		procDestroyIcon.Call(uintptr(iconOK))
	}
	if iconBad != 0 {
		procDestroyIcon.Call(uintptr(iconBad))
	}
}

func wndProc(h windows.Handle, message uint32, wparam, lparam uintptr) uintptr {
	switch message {
	case wmTimer:
		refresh()
		return 0

	case wmTrayIcon:
		// Either button opens the menu. Windows convention is right-click,
		// but people reach for the left one and a menu that does nothing on
		// half the clicks reads as broken.
		if lparam == wmRButtonUp || lparam == wmLButtonUp {
			showMenu()
		}
		return 0

	case wmCommand:
		switch wparam & 0xffff {
		case cmdStatus:
			showStatus()
		case cmdPermissions:
			checkPermissions()
		case cmdLogs:
			openLogs()
		case cmdUninstall:
			go uninstallAgent()
		case cmdHide:
			procDestroyWindow.Call(uintptr(h))
		}
		return 0

	case wmDestroy:
		removeIcon()
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProc.Call(uintptr(h), uintptr(message), wparam, lparam)
	return r
}

func showMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	// The first row is the answer to "is it working?", which is why somebody
	// clicks this at all. Greyed because it is a readout, not a choice.
	_, title, _ := currentState()
	appendItem(menu, mfString|mfGrayed, 0, title)
	appendItem(menu, mfSeparator, 0, "")
	appendItem(menu, mfString, cmdStatus, "Agent Status...")
	appendItem(menu, mfString, cmdPermissions, "Check Permissions...")
	appendItem(menu, mfString, cmdLogs, "View Logs")
	appendItem(menu, mfSeparator, 0, "")
	// Hides the ICON, not the agent. "Exit" next to a security agent's name
	// reads as "switch off the monitoring", which this cannot do — the agent
	// is a SYSTEM service and keeps running.
	appendItem(menu, mfString, cmdUninstall, "Uninstall wxt-agent...")
	appendItem(menu, mfSeparator, 0, "")
	appendItem(menu, mfString, cmdHide, "Hide Tray Icon")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	// Required, or the menu does not dismiss when the person clicks elsewhere
	// — a documented quirk of tray menus.
	procSetForegroundWin.Call(uintptr(hwnd))

	procTrackPopupMenu.Call(menu, tpmRightButton|tpmBottomAlign,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
}

func appendItem(menu uintptr, flags uint32, id uint32, text string) {
	var p *uint16
	if text != "" {
		p, _ = windows.UTF16PtrFromString(text)
	}
	procAppendMenu.Call(menu, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(p)))
}

// showText puts a block of text in a message box.
func showText(title, body string) {
	t, _ := windows.UTF16PtrFromString(title)
	b, _ := windows.UTF16PtrFromString(body)
	procMessageBox.Call(uintptr(hwnd),
		uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), mbOK|mbIconInfo)
}

func fatal(what string, err error) {
	showText("wxt-agent", what+"\n\n"+err.Error())
}

// showBlockedNotice tells the user why the program they started did not open.
//
// Nothing else is done: this process exists only because Windows launched it
// instead of the blocked program, and it must not then go on to start a tray
// icon or anything else. It says what happened and exits.
func showBlockedNotice(program string) {
	what := "This application"
	if program != "" {
		what = program
	}
	showText("Blocked by your organisation",
		what+" has been blocked by your organisation's application policy.\n\n"+
			"If you need it for your work, ask your IT administrator to allow it.")
}

// checkPermissions runs the agent's own diagnostic and shows its output.
//
// Windows has no privacy database, so running the agent's own check is safe
// here and its output is what somebody needs to see.
func checkPermissions() {
	out, err := exec.Command(agentPath, "check-permissions").CombinedOutput()
	text := string(out)
	if err != nil && text == "" {
		text = fmt.Sprintf("Could not run the check: %v", err)
	}
	showText("Permissions", text)
}

// shellExecute runs a program through the shell, with a verb.
//
// "runas" is what raises the UAC prompt. The tray runs as the logged-in user
// and the agent it is removing is a service running as SYSTEM, so something
// has to ask for elevation; CreateProcess cannot, and ShellExecute can.
func shellExecute(verb, file, args string) error {
	v, err := windows.UTF16PtrFromString(verb)
	if err != nil {
		return err
	}
	f, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	a, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, v, f, a, nil, windows.SW_HIDE)
}

// uninstallAgent removes the product from this machine.
//
// On the menu because there was nowhere else to find it: the tray had no
// uninstall at all, and Add/Remove Programs is several clicks away and is not
// where somebody looks when the thing they want to remove has an icon in the
// notification area.
//
// Delegated to `wxt-agent uninstall`, the same command Add/Remove Programs
// runs, so there is one description of what "installed" means.
func uninstallAgent() {
	if !confirmUninstall() {
		return
	}

	if err := shellExecute("runas", agentPath, "uninstall --yes"); err != nil {
		// A refused UAC prompt arrives here and is not a failure to report as
		// one — the person said no.
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return
		}
		showText("Uninstall could not start",
			"Could not run the uninstaller:\n\n"+err.Error()+
				"\n\nOpen an administrator Command Prompt and run:\n    \""+agentPath+"\" uninstall")
		return
	}

	showText("Removing wxt-agent",
		"The uninstaller is running with administrator rights.\n\n"+
			"Any application the agent had blocked is being put back.\n\n"+
			"This tray icon disappears once it finishes; if it is still here in "+
			"a minute, choose Hide Tray Icon.")
}

// confirmUninstall asks first. Removing a management agent takes the machine
// out of the fleet and is not something to do on a mis-click.
func confirmUninstall() bool {
	t, _ := windows.UTF16PtrFromString("Uninstall wxt-agent")
	b, _ := windows.UTF16PtrFromString(
		"Remove wxt-agent from this computer?\n\n" +
			"This stops the agent, removes its service, its configuration and its logs, " +
			"and restores any application it had blocked.\n\n" +
			"The machine stays listed in the portal until an administrator removes it there.")

	r, _, _ := procMessageBox.Call(uintptr(hwnd),
		uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)),
		mbYesNo|mbIconWarning)
	return r == idYes
}
