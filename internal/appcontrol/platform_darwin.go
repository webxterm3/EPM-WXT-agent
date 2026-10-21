//go:build darwin

package appcontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
)

// psPath is absolute rather than found on PATH: this runs as root, and
// resolving a helper through an inherited PATH is how a daemon ends up running
// somebody else's binary.
const psPath = "/bin/ps"

func platformProcessLister() ProcessLister { return darwinProcs{} }
func platformKiller() Killer               { return posixKiller{} }

func platformLocker(logger *zap.Logger) Locker { return &darwinLocker{logger: logger} }

// enforcementCollector is the inventory scan used for reconcile passes.
//
// Signatures are skipped: reading them is one codesign process per
// application, which is the expensive part of a scan, and it runs here every
// two minutes rather than once a day. The publisher a rule needs still comes
// through — from the daily full scan, by way of the enforcer's index — so
// what is lost is only the publisher of an application installed in the last
// day and never scanned properly, which the next full scan corrects.
func enforcementCollector() appinventory.Collector {
	return appinventory.FastPlatformCollector()
}

type darwinProcs struct{}

// List reads the process table through ps.
//
// comm on macOS is the full executable path, which is exactly what is needed
// and what neither /proc (absent here) nor a cgo-free gopsutil reliably give.
func (darwinProcs) List(ctx context.Context) ([]RunningProcess, error) {
	cmd := exec.CommandContext(ctx, psPath, "-axo", "pid=,ppid=,comm=")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ps: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return parsePS(out.String()), nil
}

// parsePS turns `ps -axo pid=,ppid=,comm=` output into records.
//
// Split on whitespace only twice: an executable path contains spaces far more
// often than not on macOS ("/Applications/Google Chrome.app/..."), and a
// plain Fields() would shred it.
func parsePS(out string) []RunningProcess {
	var procs []RunningProcess
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		rest := strings.TrimLeft(parts[1], " ")
		parts = strings.SplitN(rest, " ", 2)
		if len(parts) != 2 {
			continue
		}
		ppid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		procs = append(procs, RunningProcess{
			PID: pid, PPID: ppid,
			ExePath: strings.TrimSpace(parts[1]),
		})
	}
	return procs
}

type posixKiller struct{}

func (posixKiller) Kill(pid int) error {
	// PID 1 and the kernel task are refused outright. Nothing should ever
	// produce them here — they are under protected paths — but a kill of
	// launchd panics the machine, so it does not rest on that.
	if pid <= 1 {
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

// darwinLocker prevents an application from launching by withholding the
// execute bit from the binary inside its bundle.
//
// This is not Endpoint Security. A user with admin rights can chmod it back,
// and this is said plainly in the portal rather than implied otherwise. What
// it does do is stop the application launching for an ordinary user, through
// the Dock, Spotlight or Finder, without deleting anything and with the
// original mode restorable.
//
// # App Management
//
// From macOS 14, modifying a file inside an .app bundle requires the App
// Management privacy permission, and a process without it gets EPERM — not a
// crash, not a prompt, just a refusal. That makes this mechanism conditional
// on a permission the agent may not have been granted, which is why it is the
// SECOND line of enforcement and not the only one: whatever happens here, the
// process sweep still closes the application. Launch prevention turns "it
// never opens" into "it opens and closes", and the difference is reported
// rather than hidden, because an operator deciding whether to rely on this
// needs to know which one their fleet is getting.
type darwinLocker struct{ logger *zap.Logger }

func (*darwinLocker) Kind() string { return "execute-bit" }

func (l *darwinLocker) Lock(t Target) error {
	bin, err := lockTargetBinary(t)
	if err != nil {
		return err
	}

	fi, err := os.Stat(bin)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	if mode&0o111 == 0 {
		return nil // already locked; Lock is called every pass
	}
	if err := os.Chmod(bin, mode&^0o111); err != nil {
		return describeChmodFailure(bin, err)
	}
	return nil
}

// describeChmodFailure turns a bare errno into something actionable.
//
// "operation not permitted" on a file the agent owns, running as root, is
// macOS App Management and nothing else — and nobody reading it would guess
// that. The message has to name the permission, because the fix is a checkbox
// in System Settings and not anything in this product.
func describeChmodFailure(path string, err error) error {
	if errors.Is(err, syscall.EPERM) && strings.Contains(path, ".app/") {
		return fmt.Errorf("macOS refused to modify %s: grant wxt-agent App Management in "+
			"System Settings › Privacy & Security › App Management. Until then this application "+
			"is closed when it runs rather than prevented from launching", path)
	}
	return err
}

func (l *darwinLocker) Unlock(t Target) error {
	bin, err := lockTargetBinary(t)
	if err != nil {
		// An application that has been uninstalled since it was locked has
		// nothing left to restore, and saying so as an error would keep the
		// record forever and retry it every pass.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	fi, err := os.Stat(bin)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	mode := fi.Mode().Perm()
	if mode&0o111 != 0 {
		return nil
	}
	// Restore execute wherever read is already granted, which reproduces the
	// mode every application bundle ships with (0755) without having to have
	// recorded it. Writing 0755 unconditionally would widen a binary that was
	// deliberately owner-only.
	restored := mode | ((mode & 0o444) >> 2)
	if err := os.Chmod(bin, restored); err != nil {
		return describeChmodFailure(bin, err)
	}
	return nil
}

// lockTargetBinary is the file inside a bundle that actually runs.
func lockTargetBinary(t Target) (string, error) {
	if t.ExePath != "" {
		return t.ExePath, nil
	}
	if t.Path == "" {
		return "", fmt.Errorf("no path to lock")
	}
	if !strings.HasSuffix(t.Path, ".app") {
		return t.Path, nil
	}
	return "", fmt.Errorf("the executable inside %s is not known", t.Path)
}

// applicationPathFor maps a running executable back to the application a user
// would recognise.
//
// Browsers and Electron applications run most of their processes out of nested
// helper bundles several levels inside the outer one — a Chrome tab is
// ".../Google Chrome.app/Contents/Frameworks/.../Google Chrome Helper.app/...".
// Matching on the innermost bundle would mean a rule naming Chrome does not
// match Chrome's own renderers, so the OUTERMOST .app wins.
func applicationPathFor(exePath string) string {
	n := strings.ReplaceAll(exePath, `\`, "/")
	lower := strings.ToLower(n)
	if i := strings.Index(lower, ".app/"); i >= 0 {
		return n[:i+len(".app")]
	}
	return exePath
}

// installWatchDirs are the places macOS software actually lands.
//
// /Applications and each user's own Applications folder cover anything with a
// bundle — including Homebrew casks, which brew moves there rather than
// leaving in the Caskroom. The Caskroom itself is watched for the casks that
// install something other than an application, and Cellar for formulae, which
// are the ones no other mechanism would ever notice.
func installWatchDirs() []string {
	dirs := []string{"/Applications"}
	dirs = append(dirs, appinventory.UserApplicationDirs()...)
	for _, prefix := range appinventory.DefaultHomebrewPrefixes {
		dirs = append(dirs, prefix+"/Caskroom", prefix+"/Cellar")
	}
	return dirs
}

// platformElevator is not implemented yet on macOS.
//
// The mechanism is not the hard part — the agent is a root LaunchDaemon and
// `launchctl asuser` adopts the target user's session WITHOUT dropping
// privileges, so a process started that way already runs as root in their
// GUI session. What is missing is interception: macOS offers no supported way
// to catch a launch and redirect it without an Endpoint Security entitlement
// this product does not hold, so "the user double-clicks and it comes up
// elevated" cannot be delivered the way it can on Windows.
//
// It reports unsupported rather than quietly doing nothing, so a rule asking
// for elevation shows up in the portal as a rule this platform cannot honour.
// That is the whole lesson of the publisher bug and the elevate no-op: a
// feature that silently does nothing is indistinguishable from a broken one.
func platformElevator(*zap.Logger) Elevator {
	return unsupportedElevator{
		reason: "macOS cannot intercept a launch without the Endpoint Security entitlement; " +
			"elevation is not available on this platform yet",
	}
}
