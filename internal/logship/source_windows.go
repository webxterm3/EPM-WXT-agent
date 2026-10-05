//go:build windows

package logship

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WinEventLogSource reads the Windows Event Log.
//
// It shells out to wevtutil rather than binding EvtQuery: the agent already
// runs as SYSTEM so it has the access either way, and the subscription API's
// callback model would need a cgo-free reimplementation of the whole render
// path to produce what /f:RenderedXml gives directly.
type WinEventLogSource struct {
	// Channels to read. Empty means DefaultWindowsChannels.
	Channels []string

	// KeepRaw stores each event's structured data alongside the rendered
	// message. Errors and criticals keep theirs regardless.
	KeepRaw bool

	mu sync.Mutex
	// missing records channels wevtutil rejected, so a machine without Sysmon
	// does not log the same failure every thirty seconds forever.
	missing map[string]bool
}

// NewWinEventLogSource returns the Windows system log source.
func NewWinEventLogSource() *WinEventLogSource {
	return &WinEventLogSource{missing: map[string]bool{}}
}

func (s *WinEventLogSource) Name() string { return winSourceName }

// Close is a no-op: each read owns its own process.
func (s *WinEventLogSource) Close() error { return nil }

func (s *WinEventLogSource) channels() []string {
	if len(s.Channels) > 0 {
		return s.Channels
	}
	return DefaultWindowsChannels
}

// wevtutilPath resolves the tool under SystemRoot rather than through PATH: a
// SYSTEM service must not execute whatever a writable PATH entry resolves to.
func wevtutilPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "wevtutil.exe")
}

func (s *WinEventLogSource) Read(ctx context.Context, from Position, limit int) ([]Record, Position, error) {
	channels := s.channels()

	// The limit is split across channels rather than spent in order. Security
	// on a domain-joined machine out-produces every other channel combined, so
	// reading first-come would starve the rest indefinitely.
	perChannel := limit / len(channels)
	if perChannel < 50 {
		perChannel = 50
	}

	var (
		records []Record
		next    = from
		failed  []string
	)

	for _, ch := range channels {
		if ctx.Err() != nil {
			break
		}

		lastID := parseUint(from.Get(ch))
		out, err := s.query(ctx, ch, lastID, from.Since, perChannel)
		if err != nil {
			if s.noteMissing(ch) {
				failed = append(failed, fmt.Sprintf("%s: %v", ch, err))
			}
			continue
		}
		s.clearMissing(ch)

		recs, highest, parseErr := parseWinEvents(bytes.NewReader(out), s.KeepRaw, perChannel)
		if parseErr != nil && len(recs) == 0 {
			failed = append(failed, fmt.Sprintf("%s: %v", ch, parseErr))
			continue
		}

		records = append(records, recs...)
		if highest > lastID {
			next = next.Set(ch, formatUint(highest))
		}
	}

	// Channels are reported only when nothing at all came back. A machine
	// without Sysmon should not turn every poll into an error while the logs
	// that do exist are collected fine.
	if len(records) == 0 && len(failed) > 0 {
		return nil, from, fmt.Errorf("wevtutil: %s", truncate(strings.Join(failed, "; "), 512))
	}
	return records, next, nil
}

// query runs wevtutil for one channel.
func (s *WinEventLogSource) query(ctx context.Context, channel string, afterID uint64, since time.Time, count int) ([]byte, error) {
	// Oldest-first (/rd:false) so the record id advances monotonically. Read
	// newest-first and a partial batch would leave the cursor past events that
	// were never shipped.
	args := []string{
		"qe", channel,
		"/f:RenderedXml",
		"/e:Events",
		"/rd:false",
		fmt.Sprintf("/c:%d", count),
		"/q:" + winQuery(afterID, since),
	}

	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, wevtutilPath(), args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", truncate(msg, 256))
	}
	return out.Bytes(), nil
}

// winQuery builds the XPath filter.
//
// The record id is used once there is one because it is exact. Before that —
// a fresh install — the filter is by time, so the agent picks up the recent
// past instead of shipping every event the machine has ever retained.
func winQuery(afterID uint64, since time.Time) string {
	if afterID > 0 {
		return fmt.Sprintf("*[System[(EventRecordID>%d)]]", afterID)
	}
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}
	return fmt.Sprintf("*[System[TimeCreated[@SystemTime>='%s']]]",
		since.UTC().Format("2006-01-02T15:04:05.000Z"))
}

// noteMissing records a channel failure, reporting true only the first time so
// the log carries the problem once rather than on every poll.
func (s *WinEventLogSource) noteMissing(channel string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.missing == nil {
		s.missing = map[string]bool{}
	}
	if s.missing[channel] {
		return false
	}
	s.missing[channel] = true
	return true
}

func (s *WinEventLogSource) clearMissing(channel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.missing, channel)
}
