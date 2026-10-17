//go:build windows

package appcontrol

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
)

func platformProcessLister() ProcessLister { return windowsProcs{} }
func platformKiller() Killer               { return windowsKiller{} }

func platformLocker(logger *zap.Logger) Locker { return &windowsLocker{logger: logger} }

// enforcementCollector reads the uninstall registry, which is cheap — no
// filesystem walk — so the reconcile pass uses the ordinary collector.
func enforcementCollector() appinventory.Collector { return appinventory.FastPlatformCollector() }

type windowsProcs struct{}

// List walks the process table and resolves each one's image path.
//
// A process whose path cannot be read is returned with an empty ExePath
// rather than dropped: the caller skips it, and dropping it here would hide
// how many there were.
func (windowsProcs) List(context.Context) ([]RunningProcess, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}

	var procs []RunningProcess
	for {
		procs = append(procs, RunningProcess{
			PID:     int(entry.ProcessID),
			PPID:    int(entry.ParentProcessID),
			ExePath: imagePath(entry.ProcessID),
		})
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return procs, nil
}

// imagePath resolves a PID to the full path of its executable.
//
// PROCESS_QUERY_LIMITED_INFORMATION is the right-sized access: it is enough
// for the image path and, unlike PROCESS_QUERY_INFORMATION, it is granted for
// protected processes, so the paths that matter do not come back blank.
func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseHandle(h) }()

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

type windowsKiller struct{}

func (windowsKiller) Kill(pid int) error {
	if pid <= 4 {
		// 0 and 4 are the idle and system processes. Terminating either is not
		// something a policy should ever be able to ask for.
		return fmt.Errorf("refusing to terminate pid %d", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.TerminateProcess(h, 1)
}

// ifeoKey is where Windows looks before launching any executable.
const ifeoKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

// debuggerValue is the value name Windows reads. Setting it makes Windows run
// the named program INSTEAD of the one that was asked for, passing the
// original command line along — which is a documented debugging facility and
// the only supported way to refuse a launch without a WDAC policy.
const debuggerValue = "Debugger"

// windowsLocker prevents an application from launching through Image File
// Execution Options.
//
// Two honest limitations, both surfaced in the portal rather than left to be
// discovered:
//
//	IFEO keys on the executable's FILE NAME, not its full path. Blocking
//	"chrome.exe" blocks every chrome.exe on the machine, wherever it was
//	installed from. For application control that is usually what was meant —
//	it closes the "copy it somewhere else and run it" hole for free — but a
//	rule written against one specific path is applied more broadly than it
//	reads, so the path is recorded with the lock and shown with the event.
//
//	It needs administrator rights to set, which the agent has, and to remove,
//	which an administrator on the machine also has. This is managed-fleet
//	application control, not a boundary against the machine's own admin.
type windowsLocker struct{ logger *zap.Logger }

func (*windowsLocker) Kind() string { return "image-file-execution-options" }

func (l *windowsLocker) Lock(t Target) error {
	name, err := ifeoName(t)
	if err != nil {
		return err
	}
	notice, err := blockNoticeCommand()
	if err != nil {
		return err
	}

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ifeoKey+`\`+name, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("creating the launch-block entry for %s: %w", name, err)
	}
	defer func() { _ = k.Close() }()

	if existing, _, err := k.GetStringValue(debuggerValue); err == nil {
		if existing == notice {
			return nil // already locked; Lock runs every pass
		}
		if !isOurNotice(existing) {
			// Somebody else — a debugger, another management tool — already
			// owns this entry. Overwriting it would break whatever set it and
			// leave nothing able to put it back.
			return fmt.Errorf("%s already has a debugger set by something else (%s); not overwriting it", name, existing)
		}
	}

	return k.SetStringValue(debuggerValue, notice)
}

func (l *windowsLocker) Unlock(t Target) error {
	name, err := ifeoName(t)
	if err != nil {
		return err
	}
	path := ifeoKey + `\` + name

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}

	existing, _, err := k.GetStringValue(debuggerValue)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		// Nothing of ours to remove.
	case err != nil:
		_ = k.Close()
		return err
	case !isOurNotice(existing):
		// Replaced since we set it. Leaving it is the only safe move.
		_ = k.Close()
		return nil
	default:
		if err := k.DeleteValue(debuggerValue); err != nil {
			_ = k.Close()
			return err
		}
	}

	// The key is removed only when nothing else is left in it: these entries
	// carry unrelated settings (GlobalFlag, MitigationOptions) that other
	// tools own, and deleting the key would silently take those with it.
	names, _ := k.ReadValueNames(0)
	subkeys, _ := k.ReadSubKeyNames(0)
	_ = k.Close()

	if len(names) == 0 && len(subkeys) == 0 {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ifeoName is the executable file name an IFEO entry keys on.
func ifeoName(t Target) (string, error) {
	p := t.ExePath
	if p == "" {
		p = t.Path
	}
	base := filepath.Base(strings.ReplaceAll(p, "/", `\`))
	if base == "" || base == "." || base == `\` {
		return "", fmt.Errorf("no executable name to block for %q", t.Name)
	}
	if !strings.EqualFold(filepath.Ext(base), ".exe") {
		// IFEO only applies to executables. An installer directory or an MSI
		// has no launch to intercept, and writing a key for it would be an
		// entry that silently never fires.
		return "", fmt.Errorf("%s has no executable to block (%s)", t.Name, base)
	}
	return base, nil
}

// blockNoticeCommand is what Windows runs in place of a blocked program.
//
// The status-area binary is used rather than the agent: it is built for the
// GUI subsystem, so it shows the message without a console window flashing up
// first — which on a blocked launch is the whole user-visible experience.
func blockNoticeCommand() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	notice := filepath.Join(filepath.Dir(exe), "wxt-agent-tray.exe")
	if _, err := os.Stat(notice); err != nil {
		return "", fmt.Errorf("the block-notice program is missing at %s: %w", notice, err)
	}
	return `"` + notice + `" --blocked`, nil
}

// isOurNotice reports whether a Debugger value is one this product set.
func isOurNotice(v string) bool {
	l := strings.ToLower(v)
	return strings.Contains(l, "wxt-agent-tray.exe") && strings.Contains(l, "--blocked")
}

// applicationPathFor is the executable itself on Windows: there is no bundle
// to walk up to.
func applicationPathFor(exePath string) string { return exePath }

// installWatchDirs are the places Windows software actually lands.
//
// The uninstall registry is the authoritative list, but reading it every few
// seconds is not free, and plenty of software — portable packages, anything
// installed without admin rights — never appears in it at all. These are the
// directories those land in.
func installWatchDirs() []string {
	dirs := []string{
		`C:\Program Files`,
		`C:\Program Files (x86)`,
	}
	if root := os.Getenv("ChocolateyInstall"); root != "" {
		dirs = append(dirs, root+`\lib`)
	} else {
		dirs = append(dirs, appinventory.DefaultChocolateyRoot+`\lib`)
	}
	// Per-user installs: the ones somebody performs precisely because they
	// have no administrator rights, which is the case least-privilege work
	// exists to control.
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		dirs = append(dirs, local+`\Programs`)
	}
	return dirs
}
