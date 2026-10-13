//go:build !windows

package osuser

import "os/user"

// Lookup is the plain lookup: outside Windows a bare name is the account name.
func Lookup(username string) (*user.User, error) {
	return user.Lookup(username)
}
