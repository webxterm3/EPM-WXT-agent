package agent

import (
	"fmt"
	"net/url"
	"strings"
)

// Where an update may be fetched from.
//
// The backend sends a URL and the agent downloaded it. There was no check of
// any kind: not the scheme, not the host, nothing compared against the server
// the agent is actually enrolled with. A backend that was wrong — misconfigured,
// or in somebody else's hands — could name any host on the internet and the
// agent would fetch and run it as root.
//
// That is a wider hole than it looks, because the bytes are then EXECUTED. The
// hash check beside this one proves the package matches what the server
// published; it says nothing about whether that server should have been asked.

// updateHostMismatch is returned when the URL points somewhere else entirely.
type updateHostMismatch struct{ want, got string }

func (e updateHostMismatch) Error() string {
	return fmt.Sprintf("the update points at %s, but this agent is enrolled with %s — "+
		"refusing to fetch code from a host it was not configured to trust", e.got, e.want)
}

// checkUpdateSource reports whether an update URL may be fetched.
//
// Compared on HOST only, not the full prefix: the configured server carries a
// scheme and sometimes a path, and the download sits under /agent/download/.
// Port is part of the identity — a different port on the same machine is a
// different service, and often a different trust boundary.
//
// An empty configured host refuses everything. An agent that does not know
// who it works for cannot judge where an update should come from, and
// defaulting to "allow" there would make a missing config into no check at
// all — which is how this ended up unchecked in the first place.
func checkUpdateSource(rawURL, configuredHost string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("the update URL could not be read: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("the update URL names no host: %s", rawURL)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		// file:// would read off the local disk, where an unprivileged user
		// may be able to write.
		return fmt.Errorf("an update may only be fetched over http or https, not %q", u.Scheme)
	}

	want := normaliseHost(configuredHost)
	if want == "" {
		return fmt.Errorf("this agent has no configured server, so it cannot judge " +
			"whether an update URL should be trusted")
	}
	if got := strings.ToLower(u.Host); got != want {
		return updateHostMismatch{want: want, got: got}
	}
	return nil
}

// normaliseHost reduces a configured server address to host:port.
//
// The config carries it in several shapes — "https://host:8082",
// "host:8082", with or without a trailing slash — because different parts of
// the product write it differently.
func normaliseHost(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		v = "//" + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// updateIsPlaintext reports whether the package will cross the network
// unprotected.
//
// Not a refusal. A deployment on a private network over http is a real choice
// somebody made, and breaking their updates is not this function's decision.
// But the agent must not imply the download was protected when it was not:
// over http, an attacker on the path rewrites the package AND the hash file
// in the same breath, because both are fetched the same way from the same
// host. The hash check is then worth nothing against them, and only the log
// can say so.
func updateIsPlaintext(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(u.Scheme, "http")
}
