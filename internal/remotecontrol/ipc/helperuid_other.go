//go:build !darwin

package ipc

import "go.uber.org/zap"

// warnIfHelperIsRoot is a macOS concern: only there does the account a process
// runs as decide which permission store is consulted.
func warnIfHelperIsRoot(_ *zap.Logger, _ int) {}
