package logship

import (
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":    "example.com",
		"example.com":     "example.com",
		`"example.com."`:  "example.com",
		"example.com:443": "example.com",
		"  example.com  ": "example.com",
		"WWW.Google.COM.": "www.google.com",
	}
	for in, want := range cases {
		// The same site arriving as three different strings makes every count
		// of "who visited what" quietly wrong.
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsInterestingDomain(t *testing.T) {
	keep := []string{
		"example.com",
		"www.google.com",
		"login.microsoftonline.com",
		"s3.ap-south-1.amazonaws.com",
	}
	for _, d := range keep {
		if !isInterestingDomain(d) {
			t.Errorf("%q was dropped but is real website activity", d)
		}
	}

	// These are the bulk of DNS traffic by count and answer no question anyone
	// asks, so shipping them is most of what would make this unaffordable.
	drop := []string{
		"",
		"printer.local",
		"_airplay._tcp.local",
		"_companion-link._tcp",
		"1.0.168.192.in-addr.arpa",
		"b.a.9.8.ip6.arpa",
		"nas.lan",
		"router.home",
		"localhost",
		"wxt-laptop-07",
		"93.184.216.34",
		redactionMarker,
	}
	for _, d := range drop {
		if isInterestingDomain(d) {
			t.Errorf("%q was kept but is local or reverse-lookup noise", d)
		}
	}
}

func TestDomainFromWinDNSMessage(t *testing.T) {
	cases := map[string]string{
		"DNS query is completed for the name example.com, type 1, query options 0x8000 with status 0 Results 93.184.216.34;": "example.com",
		"DNS query is called for the name Login.Microsoftonline.COM, type 28":                                                "login.microsoftonline.com",
		// The fallback shape, used when the provider's metadata is missing.
		"QueryName=github.com QueryType=1 QueryStatus=0": "github.com",
		// Not a lookup at all.
		"The DNS client service has started.": "",
		// A reverse lookup must not be reported as a visited site.
		"DNS query is completed for the name 1.0.168.192.in-addr.arpa, type 12": "",
	}
	for msg, want := range cases {
		if got := domainFromWinDNSMessage(msg); got != want {
			t.Errorf("domainFromWinDNSMessage(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestDomainFromMDNSMessage(t *testing.T) {
	cases := map[string]string{
		"[R12] getaddrinfo <mask.hash: 'example.com'> Type A": "example.com",
		"Q example.com. Addr": "example.com",
		"mDNSCoreReceiveResponse: 'www.google.com.' A 142.250.0.1": "www.google.com",
		// Bonjour discovery, not browsing.
		"Q _companion-link._tcp.local. PTR": "",
		// A sentence with no hostname must not yield a fictitious domain.
		"Adding update to active question list": "",
	}
	for msg, want := range cases {
		if got := domainFromMDNSMessage(msg); got != want {
			t.Errorf("domainFromMDNSMessage(%q) = %q, want %q", msg, got, want)
		}
	}
}

// When macOS withholds the hostname there is nothing to report, and guessing
// from the rest of the line would invent activity that never happened.
func TestRedactedMessageYieldsNoDomain(t *testing.T) {
	msg := "[R12] getaddrinfo <private> Type A"
	if got := domainFromMDNSMessage(msg); got != "" {
		t.Errorf("extracted %q from a redacted line", got)
	}
	if !looksRedacted(msg) {
		t.Error("looksRedacted did not recognise the redaction marker")
	}
}

func TestDNSRecordKeepsTheContextAndTheOriginal(t *testing.T) {
	base := Record{
		Timestamp: time.Date(2026, time.September, 27, 10, 0, 0, 0, time.UTC),
		Source:    "macos-unified",
		Channel:   "com.apple.mDNSResponder",
		Level:     "debug",
		User:      `CORP\yesveer`,
		Process:   "mDNSResponder",
		Message:   "[R12] getaddrinfo <mask.hash: 'example.com'> Type A",
	}

	got := dnsRecord(base, "example.com")

	if got.Source != "dns" {
		t.Errorf("Source = %q, want dns", got.Source)
	}
	if got.Message != "example.com" {
		t.Errorf("Message = %q, want the bare domain so the archive is groupable", got.Message)
	}
	// Who and when are the whole point of the record; losing them would leave
	// a list of domains nobody can attribute.
	if !got.Timestamp.Equal(base.Timestamp) {
		t.Errorf("Timestamp = %s, want %s", got.Timestamp, base.Timestamp)
	}
	if got.User != base.User {
		t.Errorf("User = %q, want %q", got.User, base.User)
	}
	if got.Raw != base.Message {
		t.Errorf("Raw = %q, want the original line %q", got.Raw, base.Message)
	}
}
