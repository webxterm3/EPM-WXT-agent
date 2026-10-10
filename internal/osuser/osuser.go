// Package osuser resolves a local account on the platforms the agent runs on.
//
// os/user.Lookup takes a bare name, which is correct on Linux and macOS and
// frequently wrong on Windows. A laptop joined to Microsoft Entra ID holds its
// accounts as AzureAD\name, and a domain-joined one as DOMAIN\name — while
// C:\Users, the USERNAME variable and the sign-in screen all show the bare
// name. Looking that bare name up fails with "No mapping between account names
// and security IDs was done", which is why an agent configured against a
// perfectly normal corporate laptop could not find the account it was told to
// use.
//
// So on Windows the bare name is treated as one candidate among several rather
// than as the answer.
package osuser

import (
	"os/user"
	"strings"
)

// Candidates returns the names worth looking up for username, most likely
// first. Exported for the tests; Lookup is what callers want.
//
// hostname and userDomain are passed in rather than read here so the ordering
// can be tested on any platform.
func Candidates(username, hostname, userDomain string) []string {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}

	// A name that already carries a domain is tried exactly as given first:
	// whoever configured it that way knows something we do not.
	bare := username
	if i := strings.LastIndex(username, `\`); i >= 0 {
		bare = username[i+1:]
	}

	ordered := []string{username}
	// With nothing after the separator there is no name to qualify, and
	// prefixing the empty string just buys three guaranteed-failed lookups.
	if bare != "" {
		// AzureAD is the literal, fixed prefix Windows uses for Entra ID
		// accounts on a joined device — it is not the tenant name.
		ordered = append(ordered, bare, `AzureAD\`+bare)
		if hostname != "" {
			ordered = append(ordered, hostname+`\`+bare)
		}
		if userDomain != "" {
			ordered = append(ordered, userDomain+`\`+bare)
		}
	}

	seen := make(map[string]bool, len(ordered))
	out := make([]string, 0, len(ordered))
	for _, name := range ordered {
		if name == "" || name == `\` || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		out = append(out, name)
	}
	return out
}

// lookupFirst returns the first candidate that resolves, or the error from the
// first attempt — which describes the name the caller actually configured.
func lookupFirst(candidates []string) (*user.User, error) {
	var firstErr error
	for _, name := range candidates {
		u, err := user.Lookup(name)
		if err == nil {
			return u, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = user.UnknownUserError("")
	}
	return nil, firstErr
}
