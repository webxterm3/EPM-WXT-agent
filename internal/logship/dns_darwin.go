//go:build darwin

package logship

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// DNSSource reports website activity on macOS by reading mDNSResponder's own
// log entries through the unified log.
type DNSSource struct {
	inner  *UnifiedLogSource
	logger *zap.Logger

	mu sync.Mutex
	// warned keeps the redaction notice to one line rather than one per poll.
	warned bool
	// seen and redacted measure how much of the stream the OS withheld.
	seen, redacted int
}

// NewDNSSource returns the macOS website-activity source.
func NewDNSSource(logger *zap.Logger) *DNSSource {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DNSSource{
		inner: &UnifiedLogSource{
			// Restricting to one process is what makes this affordable:
			// mDNSResponder's info-level output is small, while info level
			// across the whole system is not.
			Predicate:        `process == "` + mDNSProcess + `"`,
			IncludeInfoDebug: true,
		},
		logger: logger,
	}
}

func (s *DNSSource) Name() string { return dnsSourceName }
func (s *DNSSource) Close() error { return s.inner.Close() }

func (s *DNSSource) Read(ctx context.Context, from Position, limit int) ([]Record, Position, error) {
	// Most mDNSResponder lines carry no hostname, so the underlying read asks
	// for more than the caller wants and the filter narrows it down.
	raw, next, err := s.inner.Read(ctx, from, limit*8)
	if err != nil {
		return nil, from, err
	}

	out := make([]Record, 0, limit)
	var seen, redacted int

	for _, r := range raw {
		seen++
		if looksRedacted(r.Message) {
			redacted++
			continue
		}
		domain := domainFromMDNSMessage(r.Message)
		if domain == "" {
			continue
		}
		out = append(out, dnsRecord(r, domain))
		if len(out) >= limit {
			break
		}
	}

	s.noteRedaction(seen, redacted)
	return out, next, nil
}

// noteRedaction reports, once, when macOS is withholding the hostnames.
//
// By default the unified log replaces strings like these with <private>. A
// source that silently returned nothing would be indistinguishable from a
// machine that visited no websites, so the reason is said out loud instead.
// Turning it off is a system-wide privacy change and is left as a deliberate
// choice rather than something the agent does on its own.
func (s *DNSSource) noteRedaction(seen, redacted int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seen += seen
	s.redacted += redacted

	const minSample = 50
	if s.warned || s.seen < minSample {
		return
	}
	if s.redacted*2 < s.seen {
		return
	}

	s.warned = true
	s.logger.Warn("Website activity: macOS is withholding hostnames from the log",
		zap.Int("sampled", s.seen),
		zap.Int("redacted", s.redacted),
		zap.String("cause", "unified log private-data redaction is on by default"),
		zap.String("remedy", `run: sudo log config --mode "private_data:on" --subsystem com.apple.mDNSResponder`))
}
