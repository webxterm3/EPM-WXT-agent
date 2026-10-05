package logship

import (
	"strings"
	"testing"
	"time"
)

// A line shaped like what `log show --style ndjson` actually emits. Field
// order and the extra keys are kept so the test exercises real input rather
// than a tidied-up version of it.
const sampleUnifiedLine = `{"traceID":58150994638733316,"eventMessage":"Connection 12: received failure notification","eventType":"logEvent","source":null,"formatString":"Connection %u: received failure notification","activityIdentifier":0,"subsystem":"com.apple.network","category":"connection","threadID":2489234,"senderImageUUID":"4C4C44E9-5555-3144-A1E0-000000000000","processImagePath":"/usr/libexec/trustd","senderImagePath":"/usr/lib/libnetwork.dylib","timestamp":"2026-09-27 15:33:01.482913+0530","machTimestamp":93847362514,"messageType":"Default","processImageUUID":"7A1B2C3D-0000-0000-0000-000000000000","processID":412,"senderProgramCounter":1874432,"parentActivityIdentifier":0,"bootUUID":"11112222-3333-4444-5555-666677778888","timezoneName":""}`

func TestParseUnifiedLine(t *testing.T) {
	rec, entry, ts, ok := parseUnifiedLine([]byte(sampleUnifiedLine), false)
	if !ok {
		t.Fatal("a well-formed unified log line was rejected")
	}

	if rec.Source != "macos-unified" {
		t.Errorf("Source = %q", rec.Source)
	}
	if rec.Message != "Connection 12: received failure notification" {
		t.Errorf("Message = %q", rec.Message)
	}
	// Subsystem:category, because the subsystem alone is too coarse to filter
	// on and the category alone is ambiguous between subsystems.
	if rec.Channel != "com.apple.network:connection" {
		t.Errorf("Channel = %q, want com.apple.network:connection", rec.Channel)
	}
	if rec.Process != "trustd" {
		t.Errorf("Process = %q, want the program name not the full path", rec.Process)
	}
	if rec.Level != "info" {
		t.Errorf("Level = %q, want info for messageType Default", rec.Level)
	}
	if entry.MachTimestamp != 93847362514 {
		t.Errorf("MachTimestamp = %d", entry.MachTimestamp)
	}

	// 15:33:01.482913 +0530 is 10:03:01.482913 UTC.
	want := time.Date(2026, time.September, 27, 10, 3, 1, 482913000, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("timestamp = %s, want %s", ts.UTC(), want)
	}
	if rec.Timestamp.Location() != time.UTC {
		t.Error("records must carry UTC so machines in different zones sort together")
	}
}

func TestParseUnifiedLineSkipsUnusableInput(t *testing.T) {
	cases := map[string]string{
		"blank":               "  ",
		"array open":          "[",
		"array close":         "]",
		"trailing comma only": ",",
		"not json":            "log: Filtering the log data using ...",
		"truncated json":      `{"timestamp":"2026-09-27 15:33:01.4+0530","eventMess`,
		"no timestamp":        `{"eventMessage":"hi","messageType":"Default"}`,
		"unparseable time":    `{"timestamp":"yesterday","eventMessage":"hi"}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, ok := parseUnifiedLine([]byte(line), false); ok {
				t.Errorf("accepted a line it cannot order or read: %q", line)
			}
		})
	}
}

// Some macOS versions wrap the stream in a JSON array, leaving each line with
// a trailing comma. Rejecting those would collect nothing at all on that OS.
func TestParseUnifiedLineToleratesArrayCommas(t *testing.T) {
	if _, _, _, ok := parseUnifiedLine([]byte(sampleUnifiedLine+","), false); !ok {
		t.Error("a line with the array's trailing comma was rejected")
	}
}

func TestUnifiedLevelMapping(t *testing.T) {
	cases := map[string]string{
		"Fault":   "critical",
		"Error":   "error",
		"Default": "info",
		"Info":    "info",
		"Debug":   "debug",
		"":        "info",
	}
	for in, want := range cases {
		if got := unifiedLevel(in); got != want {
			t.Errorf("unifiedLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

// Errors and faults keep their original JSON even when raw capture is off:
// they are the records somebody actually digs into after an incident, and the
// normalised fields drop the backtrace and sender details.
func TestRawIsKeptForErrorsButNotRoutineRecords(t *testing.T) {
	routine, _, _, ok := parseUnifiedLine([]byte(sampleUnifiedLine), false)
	if !ok {
		t.Fatal("parse failed")
	}
	if routine.Raw != "" {
		t.Error("a routine record carried Raw, doubling its size for nothing")
	}

	errLine := strings.Replace(sampleUnifiedLine, `"messageType":"Default"`, `"messageType":"Error"`, 1)
	errRec, _, _, ok := parseUnifiedLine([]byte(errLine), false)
	if !ok {
		t.Fatal("parse failed")
	}
	if errRec.Raw == "" {
		t.Error("an error record lost its original JSON")
	}

	withRaw, _, _, ok := parseUnifiedLine([]byte(sampleUnifiedLine), true)
	if !ok {
		t.Fatal("parse failed")
	}
	if withRaw.Raw == "" {
		t.Error("KeepRaw did not keep the raw line")
	}
}

func TestOversizedMessageIsTruncated(t *testing.T) {
	huge := strings.Repeat("A", 200_000)
	line := strings.Replace(sampleUnifiedLine,
		"Connection 12: received failure notification", huge, 1)

	rec, _, _, ok := parseUnifiedLine([]byte(line), false)
	if !ok {
		t.Fatal("parse failed")
	}
	if len(rec.Message) > maxMessageBytes+32 {
		t.Errorf("message kept %d bytes; one runaway line can dominate a batch", len(rec.Message))
	}
	if !strings.Contains(rec.Message, "truncated") {
		t.Error("a clipped message must say so, or a reader believes they have all of it")
	}
}

func TestTruncateDoesNotSplitARune(t *testing.T) {
	s := strings.Repeat("→", 100) // 3 bytes each
	got := truncate(s, 10)
	if !strings.HasPrefix(got, "→→→") {
		t.Fatalf("unexpected prefix %q", got)
	}
	for _, r := range got {
		if r == '�' {
			t.Fatal("truncation split a multi-byte rune")
		}
	}
}

func TestCursorSkipsRecordsAlreadyShipped(t *testing.T) {
	_, entry, ts, _ := parseUnifiedLine([]byte(sampleUnifiedLine), false)

	// The cursor sits exactly on this record: it has been shipped already.
	c := unifiedCursor{last: ts, mach: entry.MachTimestamp, boot: entry.BootUUID}
	if c.isNew(entry, ts) {
		t.Error("a record at the cursor was treated as new — every read overlaps, so this duplicates")
	}

	later := entry
	later.MachTimestamp++
	if !c.isNew(later, ts) {
		t.Error("the next record within the same second was skipped — `log show --start` only takes whole seconds, so this loses records")
	}
}

// After a reboot the mach timestamp restarts near zero. Comparing it across
// boots would treat everything after the restart as old and discard it — a
// silent, total gap starting at the moment the machine came back up.
func TestCursorDoesNotDiscardEverythingAfterAReboot(t *testing.T) {
	_, entry, ts, _ := parseUnifiedLine([]byte(sampleUnifiedLine), false)
	c := unifiedCursor{last: ts, mach: entry.MachTimestamp, boot: entry.BootUUID}

	afterReboot := entry
	afterReboot.BootUUID = "99998888-7777-6666-5555-444433332222"
	afterReboot.MachTimestamp = 1204 // counter reset

	if !c.isNew(afterReboot, ts.Add(time.Minute)) {
		t.Error("records from after a reboot were discarded as already-seen")
	}
}

func TestCursorRoundTripsThroughAPosition(t *testing.T) {
	_, entry, ts, _ := parseUnifiedLine([]byte(sampleUnifiedLine), false)
	c := unifiedCursor{last: ts, mach: entry.MachTimestamp, boot: entry.BootUUID}

	// The position is what survives a restart, so anything lost here becomes a
	// duplicate or a gap the next time the agent starts.
	got := decodeUnifiedCursor(c.encode(NewPosition(time.Time{})))

	if !got.last.Equal(c.last) {
		t.Errorf("time did not survive: %s, want %s", got.last, c.last)
	}
	if got.mach != c.mach {
		t.Errorf("mach timestamp did not survive: %d, want %d", got.mach, c.mach)
	}
	if got.boot != c.boot {
		t.Errorf("boot UUID did not survive: %q", got.boot)
	}
}

func TestFreshPositionFallsBackToSince(t *testing.T) {
	since := time.Now().Add(-6 * time.Hour).UTC().Truncate(time.Second)
	c := decodeUnifiedCursor(NewPosition(since))

	// Without this a fresh install reads from the zero time and ships the
	// machine's entire retained history in one go.
	if !c.last.Equal(since) {
		t.Errorf("a fresh cursor starts at %s, want the backfill bound %s", c.last, since)
	}
}

func TestParseUintRejectsGarbage(t *testing.T) {
	if got := parseUint("12x4"); got != 0 {
		t.Errorf("parseUint(%q) = %d, want 0", "12x4", got)
	}
	if got := parseUint("93847362514"); got != 93847362514 {
		t.Errorf("parseUint round-trip = %d", got)
	}
	if got := formatUint(93847362514); got != "93847362514" {
		t.Errorf("formatUint = %q", got)
	}
}
