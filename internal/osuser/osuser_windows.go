//go:build windows

package osuser

import (
	"os"
	"os/user"
)

// Lookup finds the account, trying the domain-qualified forms Windows actually
// stores it under before giving up.
func Lookup(username string) (*user.User, error) {
	hostname, _ := os.Hostname()
	return lookupFirst(Candidates(username, hostname, os.Getenv("USERDOMAIN")))
}

// Provisionable reports whether this platform's accounts are the agent's to
// create. On Windows they are not: see the comment on Provisionable in
// osuser_other.go.
func Provisionable() bool { return false }
