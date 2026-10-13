//go:build darwin

package ipc

import "go.uber.org/zap"

// warnIfHelperIsRoot says out loud the one condition under which no amount of
// granting can work.
//
// macOS checks a root process's Screen Recording and Accessibility against the
// system store; the grant a person gives in System Settings goes into their
// own. So a root helper is refused every time while the switch sits visibly
// on — and the only way to tell from the outside is this line.
func warnIfHelperIsRoot(logger *zap.Logger, uid int) {
	if uid != 0 {
		return
	}
	logger.Error("The session helper is running as root, so macOS will refuse its permissions",
		zap.String("cause", "launchctl asuser does not change credentials; the launch must drop to the console user"),
		zap.String("consequence", "switching Accessibility or Screen Recording on changes nothing for this process"))
}
