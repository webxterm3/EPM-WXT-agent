//go:build darwin

package pendinginstall

import (
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Who asked, in terms the portal understands.
//
// The agent knows the macOS account name — "yesveer" — and the portal knows
// people by the address their directory gave them. On an Entra-synced estate
// those are different namespaces: an approver looking at a queue row that
// says "yesveer" cannot tell who that is, searching by email never matches
// it, and no decision email can be sent.
//
// There is NO single guaranteed source for the address on macOS. Measured on
// a DEP-enrolled, Intune-managed Mac: dscl's EMailAddress, NetworkUser and
// AltSecurityIdentities are all absent; Platform SSO reports nothing; the
// Company Portal's own preferences carry no address. What is present is the
// Office activation record. So this tries what exists, in order, and returns
// nothing rather than a guess — a request attributed to the WRONG person is
// worse than one attributed to none.

// emailish is a conservative shape check. Anything that fails it is treated
// as not having been found, because a malformed address in an approval queue
// is a row nobody can act on and a decision mail that bounces.
var emailish = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ConsoleUserEmail is the directory address of whoever is at the screen, or
// empty when it cannot be established.
func ConsoleUserEmail() string {
	user := ConsoleUser()
	if user == "" {
		return ""
	}
	for _, source := range emailSources {
		if addr := normaliseEmail(source(user)); addr != "" {
			return addr
		}
	}
	return ""
}

// emailSources are tried in order of how much they are worth trusting.
//
// A var so a test can supply its own; nothing replaces it at runtime.
var emailSources = []func(user string) string{
	officeActivationEmail,
	directoryEmail,
}

func normaliseEmail(raw string) string {
	addr := strings.TrimSpace(raw)
	if !emailish.MatchString(addr) {
		return ""
	}
	return strings.ToLower(addr)
}

// officeActivationEmail reads the address Office signed in with.
//
// Read through PlistBuddy rather than by opening the file, because macOS
// preferences are stored in a form that is cached by cfprefsd and is not
// reliably plain text on disk — searching the file for an address finds
// nothing even when the key is plainly there.
func officeActivationEmail(user string) string {
	return plistString(
		filepath.Join("/Users", user, "Library", "Preferences", "com.microsoft.office.plist"),
		"OfficeActivationEmailAddress")
}

// directoryEmail reads the address the local directory holds, if any. Absent
// on the machines measured, present on some directory-bound setups.
func directoryEmail(user string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read",
		"/Users/"+user, "EMailAddress").Output()
	if err != nil {
		return ""
	}
	// "EMailAddress: someone@example.com"
	_, value, found := strings.Cut(string(out), ":")
	if !found {
		return ""
	}
	return value
}

// plistString reads one string key out of a preference file.
var plistString = func(path, key string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/libexec/PlistBuddy",
		"-c", "Print :"+key, path).Output()
	if err != nil {
		return ""
	}
	return string(out)
}
