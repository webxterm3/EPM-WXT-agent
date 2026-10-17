//go:build !darwin && !windows

package appcontrol

import (
	"context"
	"fmt"
	"syscall"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
)

// Linux endpoints are not an application-control target for this product, so
// the platform pieces are present to keep the package building and do nothing.
// They report their inertness rather than pretending to enforce.

func platformProcessLister() ProcessLister { return noProcs{} }
func platformKiller() Killer               { return posixKiller{} }

func platformLocker(*zap.Logger) Locker { return noLocker{} }

func enforcementCollector() appinventory.Collector { return appinventory.FastPlatformCollector() }

type noProcs struct{}

func (noProcs) List(context.Context) ([]RunningProcess, error) { return nil, nil }

type posixKiller struct{}

func (posixKiller) Kill(pid int) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

type noLocker struct{}

func (noLocker) Kind() string { return "unsupported" }
func (noLocker) Lock(Target) error {
	return fmt.Errorf("launch prevention is not implemented on this platform")
}
func (noLocker) Unlock(Target) error { return nil }

func applicationPathFor(exePath string) string { return exePath }

// installWatchDirs is empty: application control targets Windows and macOS.
func installWatchDirs() []string { return nil }
