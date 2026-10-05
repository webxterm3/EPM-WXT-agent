//go:build windows

package logship

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DNSSource reports website activity on Windows by reading the DNS client's
// operational channel.
type DNSSource struct {
	inner  *WinEventLogSource
	logger *zap.Logger

	once    sync.Once
	enabled bool
}

// NewDNSSource returns the Windows website-activity source.
func NewDNSSource(logger *zap.Logger) *DNSSource {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DNSSource{
		inner: &WinEventLogSource{
			Channels: []string{WindowsDNSChannel},
			missing:  map[string]bool{},
		},
		logger: logger,
	}
}

func (s *DNSSource) Name() string { return dnsSourceName }
func (s *DNSSource) Close() error { return s.inner.Close() }

func (s *DNSSource) Read(ctx context.Context, from Position, limit int) ([]Record, Position, error) {
	s.once.Do(func() { s.enabled = s.enableChannel(ctx) })
	if !s.enabled {
		// Reading a disabled channel returns nothing forever. Reporting that
		// as an error surfaces it once instead of looking like a machine that
		// never goes online.
		return nil, from, errChannelDisabled
	}

	// Only a fraction of the channel's events are name lookups, so the
	// underlying read is widened and the filter narrows it back down.
	raw, next, err := s.inner.Read(ctx, from, limit*4)
	if err != nil {
		return nil, from, err
	}

	out := make([]Record, 0, limit)
	for _, r := range raw {
		domain := domainFromWinDNSMessage(r.Message)
		if domain == "" {
			continue
		}
		out = append(out, dnsRecord(r, domain))
		if len(out) >= limit {
			break
		}
	}
	return out, next, nil
}

// errChannelDisabled is returned when the DNS channel could not be turned on.
var errChannelDisabled = errDNSChannel{}

type errDNSChannel struct{}

func (errDNSChannel) Error() string {
	return "the " + WindowsDNSChannel + " channel is disabled and could not be enabled; website activity is unavailable"
}

// enableChannel turns the DNS client log on.
//
// Windows ships it disabled, so without this the source reads an empty channel
// indefinitely. The agent runs as SYSTEM, which is what this needs; if it
// fails the reason is logged rather than retried silently every poll.
func (s *DNSSource) enableChannel(ctx context.Context) bool {
	if s.channelEnabled(ctx) {
		return true
	}

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, wevtutilPath(), "sl", WindowsDNSChannel, "/e:true")
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		s.logger.Warn("Website activity: could not enable the DNS client log",
			zap.String("channel", WindowsDNSChannel),
			zap.String("detail", truncate(strings.TrimSpace(errBuf.String()), 256)),
			zap.Error(err))
		return false
	}

	s.logger.Info("Website activity: DNS client log enabled",
		zap.String("channel", WindowsDNSChannel))
	return true
}

// channelEnabled reports whether the channel is already on, so an already
// configured machine is not reconfigured on every agent start.
func (s *DNSSource) channelEnabled(ctx context.Context) bool {
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, wevtutilPath(), "gl", WindowsDNSChannel)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "enabled:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "enabled:")) == "true"
		}
	}
	return false
}
