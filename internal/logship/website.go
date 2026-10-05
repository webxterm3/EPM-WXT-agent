package logship

import (
	"regexp"
	"strings"
)

// Website activity is derived from DNS, not from the browser.
//
// Reading browsing directly would mean a browser extension per browser or a
// TLS-intercepting proxy on the endpoint; the first is unenforceable and the
// second breaks certificate pinning and reads the contents of everything. DNS
// gives the domains — which is the question "what sites was this machine
// using" actually asks — without touching page contents, and covers every
// application rather than only browsers.
//
// The trade is that it is domains, not URLs, and a cached lookup produces no
// query at all. Both are stated plainly rather than papered over.

const dnsSourceName = "dns"

// WindowsDNSChannel carries client lookups. It ships disabled, so the source
// turns it on before it can read anything.
const WindowsDNSChannel = "Microsoft-Windows-DNS-Client/Operational"

// macOS writes hostnames through mDNSResponder.
const mDNSProcess = "mDNSResponder"

// redactionMarker is what the unified log substitutes for a string the OS
// considers private. Records carrying it hold no domain at all.
const redactionMarker = "<private>"

var (
	// The rendered form: "DNS query is completed for the name example.com, type 1, ..."
	winDNSRendered = regexp.MustCompile(`(?i)for the name ([^\s,]+)`)

	// The fallback form built from EventData when provider metadata is absent.
	winDNSQueryName = regexp.MustCompile(`(?i)QueryName=([^\s]+)`)

	// mDNSResponder quotes the name it was asked to resolve.
	mdnsQuoted = regexp.MustCompile(`'([^']+)'`)

	// A bare hostname in mDNSResponder's terser lines, e.g. "Q example.com. Addr".
	mdnsBare = regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\.?\b`)
)

// normalizeDomain lowercases and strips the trailing root dot.
//
// Without this the same site arrives as three different strings — "Example.com",
// "example.com." and "example.com" — and every count of "who visited what" is
// wrong in a way nobody notices.
func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if i := strings.IndexByte(s, ':'); i > 0 {
		s = s[:i] // a port has no business in a domain
	}
	return s
}

// uninterestingSuffixes are the lookups a machine makes constantly and nobody
// will ever ask about: reverse lookups, Bonjour service discovery, and local
// network names. They are the majority of DNS traffic by count, so dropping
// them is most of what keeps this source affordable.
var uninterestingSuffixes = []string{
	".local",
	".arpa",
	".in-addr.arpa",
	".ip6.arpa",
	".lan",
	".home",
	".internal",
}

// isInterestingDomain reports whether a lookup is worth shipping.
func isInterestingDomain(d string) bool {
	if d == "" || d == redactionMarker {
		return false
	}
	// A name with no dot is a short local hostname, not a site.
	if !strings.Contains(d, ".") {
		return false
	}
	// Bonjour service names: _airplay._tcp, _companion-link._tcp and friends.
	if strings.HasPrefix(d, "_") || strings.Contains(d, "._") {
		return false
	}
	for _, suffix := range uninterestingSuffixes {
		if strings.HasSuffix(d, suffix) {
			return false
		}
	}
	// An IP literal is the answer to a lookup, not the question.
	if isIPLiteral(d) {
		return false
	}
	return true
}

// isIPLiteral reports whether s is all digits and dots.
func isIPLiteral(s string) bool {
	hasDigit := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			hasDigit = true
		case s[i] == '.':
		default:
			return false
		}
	}
	return hasDigit
}

// domainFromWinDNSMessage pulls the queried name out of a DNS-Client record.
func domainFromWinDNSMessage(msg string) string {
	if m := winDNSQueryName.FindStringSubmatch(msg); len(m) > 1 {
		if d := normalizeDomain(m[1]); isInterestingDomain(d) {
			return d
		}
	}
	if m := winDNSRendered.FindStringSubmatch(msg); len(m) > 1 {
		if d := normalizeDomain(m[1]); isInterestingDomain(d) {
			return d
		}
	}
	return ""
}

// domainFromMDNSMessage pulls a hostname out of an mDNSResponder line.
//
// The quoted form is tried first because it is unambiguous; the loose match is
// a fallback and deliberately requires a dot, so it cannot turn a word in a
// sentence into a fictitious domain.
func domainFromMDNSMessage(msg string) string {
	if strings.Contains(msg, redactionMarker) {
		return ""
	}
	for _, m := range mdnsQuoted.FindAllStringSubmatch(msg, -1) {
		if d := normalizeDomain(m[1]); isInterestingDomain(d) {
			return d
		}
	}
	for _, m := range mdnsBare.FindAllStringSubmatch(msg, -1) {
		if d := normalizeDomain(m[1]); isInterestingDomain(d) {
			return d
		}
	}
	return ""
}

// dnsRecord rewrites a platform record as a website-activity record.
//
// Message becomes the bare domain so the archive is directly groupable, and
// the original text moves to Raw for the cases where the surrounding detail —
// the query type, the status, which resolver answered — turns out to matter.
func dnsRecord(base Record, domain string) Record {
	original := base.Message
	base.Source = dnsSourceName
	base.Channel = "query"
	base.Level = "info"
	base.Message = domain
	if base.Raw == "" {
		base.Raw = truncate(original, 1024)
	}
	return base
}

// looksRedacted reports whether a message had its strings withheld by the OS.
func looksRedacted(msg string) bool { return strings.Contains(msg, redactionMarker) }
