//go:build !linux

package executor

import "fmt"

// createUser is never reached off Linux: New only calls it when
// osuser.Provisionable() says the platform's accounts are ours to create.
//
// It exists so that useradd and usermod — which do not exist on Windows or
// macOS — cannot even be compiled into those builds. The previous shared
// implementation did compile there, and on Windows it failed at exec.LookPath
// with "useradd: executable file not found in %PATH%", which killed the agent
// before it ever registered.
func (e *Executor) createUser() error {
	return fmt.Errorf("accounts are not provisioned by the agent on this platform")
}
