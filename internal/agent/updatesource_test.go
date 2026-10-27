package agent

import (
	"strings"
	"testing"
)

// The backend sends a URL and the agent downloaded it, unchecked — then ran
// the bytes as root or SYSTEM. A backend that was wrong, or in somebody else's
// hands, could name any host on the internet and have the whole fleet execute
// what it served.
func TestAnUpdateFromAnotherHostIsRefused(t *testing.T) {
	const enrolled = "http://192.168.1.8:8082"

	for _, elsewhere := range []string{
		"http://evil.example.com/agent/download/wxt-agent-arm64.dmg",
		"https://evil.example.com/agent/download/wxt-agent-arm64.dmg",
		// Same machine, different service. A different port is usually a
		// different trust boundary.
		"http://192.168.1.8:9999/agent/download/wxt-agent-arm64.dmg",
		// Lookalikes. The second is the one that matters: it STARTS WITH the
		// enrolled host:port, so a prefix comparison waves it straight
		// through while the name resolves to somebody else entirely.
		"http://192.168.1.8.evil.com/agent/download/wxt-agent-arm64.dmg",
		"http://192.168.1.8:8082.evil.com/agent/download/wxt-agent-arm64.dmg",
	} {
		if err := checkUpdateSource(elsewhere, enrolled); err == nil {
			t.Errorf("accepted an update from %s while enrolled with %s", elsewhere, enrolled)
		}
	}
}

func TestTheEnrolledServerIsAccepted(t *testing.T) {
	for _, configured := range []string{
		"http://192.168.1.8:8082",
		"http://192.168.1.8:8082/",
		"192.168.1.8:8082",
		"HTTP://192.168.1.8:8082",
	} {
		err := checkUpdateSource(
			"http://192.168.1.8:8082/agent/download/wxt-agent-arm64.dmg?t=1761", configured)
		if err != nil {
			t.Errorf("configured as %q refused its own server: %v", configured, err)
		}
	}
}

// file:// would read off local disk, where an unprivileged user may be able to
// write — turning "install an update" into "run my file as root".
func TestOnlyHTTPSchemesAreFetched(t *testing.T) {
	for _, bad := range []string{
		"file:///tmp/evil.dmg",
		"ftp://host/pkg.dmg",
		"/tmp/evil.dmg",
	} {
		if err := checkUpdateSource(bad, "http://192.168.1.8:8082"); err == nil {
			t.Errorf("accepted %q as an update source", bad)
		}
	}
}

// An agent that does not know who it works for cannot judge where an update
// should come from. Defaulting to "allow" there would turn a missing config
// into no check at all — which is exactly how this ended up unchecked.
func TestNoConfiguredServerRefusesEverything(t *testing.T) {
	for _, configured := range []string{"", "   ", "://"} {
		err := checkUpdateSource("http://192.168.1.8:8082/agent/download/x.dmg", configured)
		if err == nil {
			t.Errorf("an agent configured with %q accepted an update", configured)
		}
	}
}

// The refusal has to name both hosts. "Not authorized" sends somebody looking
// at permissions; this is a configuration mismatch and must read as one.
func TestTheRefusalNamesBothHosts(t *testing.T) {
	err := checkUpdateSource("http://elsewhere:8082/x.dmg", "http://192.168.1.8:8082")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"elsewhere:8082", "192.168.1.8:8082"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not mention %q", msg, want)
		}
	}
}

// Over http the hash check buys nothing against somebody on the path: the
// package and the sums file are fetched the same way from the same host, so
// both are rewritten together. The agent must be able to say so.
func TestPlaintextIsRecognised(t *testing.T) {
	if !updateIsPlaintext("http://192.168.1.8:8082/agent/download/x.dmg") {
		t.Error("an http URL was not recognised as unprotected")
	}
	if updateIsPlaintext("https://epm.example.com/agent/download/x.dmg") {
		t.Error("an https URL was reported as unprotected")
	}
}
