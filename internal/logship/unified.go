package logship

import (
	"encoding/json"
	"strings"
	"time"
)

// This file holds the parsing and cursor logic for the macOS unified log. It
// carries no build tag on purpose: the exec side lives in source_darwin.go, so
// the part that is easy to get subtly wrong stays testable everywhere.

const (
	// unifiedSourceName is both the Record.Source value and the bookmark key.
	unifiedSourceName = "macos-unified"

	// cursorTime and cursorMach together order records exactly.
	//
	// The timestamp alone is not enough: `log show --start` is inclusive and
	// only takes whole seconds, so every read overlaps the previous one. The
	// mach timestamp is monotonic within a boot, which lets the overlap be
	// discarded precisely instead of guessed at.
	cursorTime = "ts"
	cursorMach = "mach"
	cursorBoot = "boot"

	// maxMessageBytes bounds one record. A single runaway log line — a stack
	// dump, a base64 blob — must not be able to dominate a batch.
	maxMessageBytes = 16 << 10
)

// unifiedEntry mirrors the fields of `log show --style ndjson` that we use.
// Anything not listed here survives in Record.Raw when raw capture is on.
type unifiedEntry struct {
	Timestamp        string `json:"timestamp"`
	MachTimestamp    uint64 `json:"machTimestamp"`
	BootUUID         string `json:"bootUUID"`
	EventMessage     string `json:"eventMessage"`
	EventType        string `json:"eventType"`
	MessageType      string `json:"messageType"`
	Subsystem        string `json:"subsystem"`
	Category         string `json:"category"`
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	ProcessID        int    `json:"processID"`
}

// unifiedTimeLayouts are the shapes `log show` has been observed to emit. The
// fractional-second form is what current macOS produces; the others are
// accepted so an OS update that drops or changes precision degrades into
// slightly coarser ordering rather than into a source that silently stops.
var unifiedTimeLayouts = []string{
	"2006-01-02 15:04:05.999999-0700",
	"2006-01-02 15:04:05.999999Z0700",
	"2006-01-02 15:04:05-0700",
	time.RFC3339Nano,
}

func parseUnifiedTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range unifiedTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// unifiedLevel maps Apple's messageType onto the shared severity vocabulary.
func unifiedLevel(messageType string) string {
	switch strings.ToLower(messageType) {
	case "fault":
		return "critical"
	case "error":
		return "error"
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "default", "":
		return "info"
	default:
		return strings.ToLower(messageType)
	}
}

// processName reduces an image path to the program name, which is what an
// operator scans for. The full path stays available in Raw.
func processName(path string) string {
	if path == "" {
		return ""
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	return path
}

// truncate clips a string to n bytes on a rune boundary, marking that it was
// cut so a reader is never misled into thinking they have the whole message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…[truncated]"
}

// utf8Start reports whether b can begin a UTF-8 sequence.
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// unifiedCursor is the decoded form of the source's Position.
type unifiedCursor struct {
	last time.Time
	mach uint64
	boot string
}

func decodeUnifiedCursor(p Position) unifiedCursor {
	c := unifiedCursor{boot: p.Get(cursorBoot)}
	if v := p.Get(cursorTime); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			c.last = t
		}
	}
	if c.last.IsZero() {
		c.last = p.Since
	}
	c.mach = parseUint(p.Get(cursorMach))
	return c
}

func (c unifiedCursor) encode(p Position) Position {
	return p.
		Set(cursorTime, c.last.UTC().Format(time.RFC3339Nano)).
		Set(cursorMach, formatUint(c.mach)).
		Set(cursorBoot, c.boot)
}

// isNew reports whether an entry sits after the cursor.
//
// Within one boot the mach timestamp decides, because it is monotonic and has
// finer resolution than the string timestamp. Across a reboot it resets to
// near zero, so comparing it would discard everything after the restart — the
// wall-clock time is the only thing still meaningful there.
func (c unifiedCursor) isNew(e unifiedEntry, ts time.Time) bool {
	if c.last.IsZero() {
		return true
	}
	if e.BootUUID != "" && e.BootUUID == c.boot && e.MachTimestamp > 0 && c.mach > 0 {
		return e.MachTimestamp > c.mach
	}
	return ts.After(c.last)
}

// parseUnifiedLine turns one NDJSON line into a Record.
//
// It reports ok=false for anything it cannot use — the array punctuation some
// macOS versions wrap the stream in, blank lines, entries without a usable
// timestamp — because a malformed line must skip that line and nothing more.
func parseUnifiedLine(line []byte, keepRaw bool) (Record, unifiedEntry, time.Time, bool) {
	trimmed := strings.TrimSpace(string(line))
	trimmed = strings.TrimSuffix(trimmed, ",")
	if trimmed == "" || trimmed == "[" || trimmed == "]" || !strings.HasPrefix(trimmed, "{") {
		return Record{}, unifiedEntry{}, time.Time{}, false
	}

	var e unifiedEntry
	if err := json.Unmarshal([]byte(trimmed), &e); err != nil {
		return Record{}, unifiedEntry{}, time.Time{}, false
	}

	ts, ok := parseUnifiedTime(e.Timestamp)
	if !ok {
		// Without a trustworthy time the record cannot be ordered, and an
		// out-of-order record in an audit archive is worse than a missing one.
		return Record{}, unifiedEntry{}, time.Time{}, false
	}

	channel := e.Subsystem
	if channel == "" {
		channel = e.EventType
	}
	if e.Category != "" && e.Subsystem != "" {
		channel = e.Subsystem + ":" + e.Category
	}

	rec := Record{
		Timestamp: ts.UTC(),
		Source:    unifiedSourceName,
		Channel:   channel,
		Level:     unifiedLevel(e.MessageType),
		Process:   processName(e.ProcessImagePath),
		Message:   truncate(e.EventMessage, maxMessageBytes),
	}

	// Raw doubles the payload, so it is kept only when asked for or when the
	// record is one somebody will actually dig into after an incident.
	if keepRaw || rec.Level == "error" || rec.Level == "critical" {
		rec.Raw = truncate(trimmed, maxMessageBytes)
	}
	return rec, e, ts, true
}

func parseUint(s string) uint64 {
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + uint64(s[i]-'0')
	}
	return n
}

func formatUint(n uint64) string {
	if n == 0 {
		return ""
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
