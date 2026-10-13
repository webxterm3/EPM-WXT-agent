//go:build !darwin

package main

import "go.uber.org/zap"

// requestOSPermissions is a macOS concern. Windows and Linux gate neither
// screen capture nor input injection behind a user grant, so there is nothing
// to ask for and nothing to register.
func requestOSPermissions(_ *zap.Logger) {}
