//go:build darwin

package remotecontrol

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	// permissionPollInterval is how often the agent re-checks after a refusal.
	permissionPollInterval = 10 * time.Second

	// permissionGracePeriod is how long to wait before restarting ANYWAY.
	//
	// The check is not trusted on its own. On a Mac where the helper runs from
	// inside the application bundle it reported both grants denied while the
	// row in System Settings was plainly switched on — and restarting the
	// agent made remote control work immediately. Since a restart is what
	// actually resolves it, waiting for a check that may be wrong means never
	// restarting at all.
	//
	// Long enough for somebody to find the pane and flip two switches.
	permissionGracePeriod = 60 * time.Second

	// permissionRestartCooldown stops a restart loop.
	//
	// The agent cannot see whether a restart helped, so without this a machine
	// where the permission is never granted would restart every minute for
	// ever. The marker is a file because the decision has to survive the very
	// restart it causes.
	permissionRestartCooldown = 15 * time.Minute
)

// restartMarker records when the agent last restarted itself for permissions.
const restartMarker = "/var/log/vsay/.permission-restart"

// watchForPermissions restarts the agent after a session is refused for want
// of a macOS permission.
//
// Restarting is the only thing observed to make a newly granted permission
// take effect: macOS does not reliably deliver it to a process tree that has
// already been refused, and the agent is the root of the tree every helper is
// spawned from.
//
// Started only after a session has actually been refused, so a machine that
// never uses remote control never runs this.
func (c *Controller) watchForPermissions() {
	if !c.permWatch.CompareAndSwap(false, true) {
		return // one watch at a time
	}

	go func() {
		defer c.permWatch.Store(false)

		if since, ok := timeSinceLastRestart(); ok && since < permissionRestartCooldown {
			c.logger.Info("Not restarting for permissions again so soon",
				zap.Duration("since_last", since.Round(time.Second)),
				zap.Duration("cooldown", permissionRestartCooldown))
			return
		}

		deadline := time.Now().Add(permissionGracePeriod)
		for {
			time.Sleep(permissionPollInterval)

			// Never mid-session: the check launches a helper of its own.
			if c.sessionInFlight() {
				continue
			}
			if c.permissionsGranted() {
				c.restart("the permissions are now granted")
				return
			}
			if time.Now().After(deadline) {
				// The check says no, but it has been wrong before and a
				// restart is what fixes this. Better one restart that was
				// not needed than a machine that stays broken.
				c.restart("the grace period elapsed; restarting anyway, because a restart is what makes a new grant take effect")
				return
			}
		}
	}()
}

// restart replaces this agent. launchd is KeepAlive, so it starts again at
// once.
func (c *Controller) restart(why string) {
	c.logger.Info("Restarting the agent for macOS permissions",
		zap.String("reason", why),
		zap.String("note", "launchd starts it again immediately"))

	markRestart()

	// The helper first, explicitly: it is a separate process launchd knows
	// nothing about, so exiting alone would leave it running and still holding
	// the refusal it was given before the grant.
	c.dropHelper()

	_ = c.logger.Sync()
	os.Exit(0)
}

func markRestart() {
	_ = os.MkdirAll(filepath.Dir(restartMarker), 0o755)                             // #nosec G301
	_ = os.WriteFile(restartMarker, []byte(time.Now().Format(time.RFC3339)), 0o644) // #nosec G306
}

func timeSinceLastRestart() (time.Duration, bool) {
	fi, err := os.Stat(restartMarker)
	if err != nil {
		return 0, false
	}
	return time.Since(fi.ModTime()), true
}

// permissionsGranted asks the helper, launched the way a session launches it,
// whether both grants apply. Exit status 0 means yes.
func (c *Controller) permissionsGranted() bool {
	helperPath := c.helperPath
	if helperPath == "" {
		var err error
		helperPath, err = EnsureHelper(defaultHelperDir())
		if err != nil {
			return false
		}
	}

	uid, err := consoleUID()
	if err != nil {
		return false // nobody at the screen; nothing to check against
	}

	return exec.Command("/bin/launchctl", "asuser", strconv.Itoa(uid),
		helperPath, "--check-permissions").Run() == nil
}

// consoleUID returns the uid of whoever owns the graphical console.
//
// /dev/console belongs to whoever is logged in at the screen, which makes
// stat'ing it the simplest reliable way to find them.
func consoleUID() (int, error) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("unexpected stat type for /dev/console")
	}
	return int(st.Uid), nil
}
