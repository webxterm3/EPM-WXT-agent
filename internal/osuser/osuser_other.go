//go:build !windows

package osuser

import (
	"os/user"
	"runtime"
)

// Lookup is the plain lookup: outside Windows a bare name is the account name.
func Lookup(username string) (*user.User, error) {
	return user.Lookup(username)
}

// Provisionable reports whether a missing account is the agent's to create.
//
// Only on Linux, where the agent owns a dedicated service account and
// provisions it with useradd. A macOS or Windows endpoint already has the
// person's own account — created by the company's directory, not by us — and
// adding a second local account to a managed laptop is a change that belongs
// to whoever runs that fleet, not to a monitoring agent.
func Provisionable() bool { return runtime.GOOS == "linux" }
