package logship

import (
	"strings"
	"testing"
	"time"
)

// Shaped like real `wevtutil qe /f:RenderedXml /e:Events` output, including the
// CRLF line endings and trailing blank lines Windows puts in rendered messages.
const sampleWinEvents = `<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-27T10:03:01.4829130Z"/><EventRecordID>884412</EventRecordID><Correlation/><Execution ProcessID="756" ThreadID="4032"/><Channel>Security</Channel><Computer>WXT-LAPTOP-07</Computer><Security/></System><EventData><Data Name="SubjectUserSid">S-1-0-0</Data><Data Name="TargetUserName">yesveer</Data><Data Name="TargetDomainName">CORP</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">10.0.4.91</Data></EventData><RenderingInfo Culture="en-US"><Message>An account was successfully logged on.&#13;&#10;&#13;&#10;Logon Type:			10&#13;&#10;&#13;&#10;&#13;&#10;</Message><Level>Information</Level><Task>Logon</Task><Opcode>Info</Opcode><Channel></Channel><Provider>Microsoft-Windows-Security-Auditing</Provider></RenderingInfo></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Error"/><EventID Qualifiers="0">1000</EventID><Level>2</Level><TimeCreated SystemTime="2026-09-27T10:05:22.1000000Z"/><EventRecordID>884413</EventRecordID><Channel>Application</Channel><Computer>WXT-LAPTOP-07</Computer><Security UserID="S-1-5-21-1111-2222-3333-1001"/></System><EventData><Data Name="AppName">notepad.exe</Data><Data Name="ExceptionCode">c0000005</Data></EventData><RenderingInfo Culture="en-US"><Message>Faulting application name: notepad.exe</Message><Level>Error</Level><Provider>Application Error</Provider></RenderingInfo></Event>
</Events>`

func parseSample(t *testing.T, doc string, keepRaw bool, limit int) ([]Record, uint64) {
	t.Helper()
	recs, highest, err := parseWinEvents(strings.NewReader(doc), keepRaw, limit)
	if err != nil {
		t.Fatalf("parseWinEvents: %v", err)
	}
	return recs, highest
}

func TestParseWinEvents(t *testing.T) {
	recs, highest := parseSample(t, sampleWinEvents, false, 0)

	if len(recs) != 2 {
		t.Fatalf("parsed %d events, want 2", len(recs))
	}
	if highest != 884413 {
		t.Errorf("highest EventRecordID = %d, want 884413", highest)
	}

	logon := recs[0]
	if logon.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", logon.EventID)
	}
	if logon.Channel != "Security" {
		t.Errorf("Channel = %q", logon.Channel)
	}
	// Level 0 is "undefined", which is what every Security audit record uses.
	// Reporting it as unknown would make the most important channel on the
	// machine impossible to filter.
	if logon.Level != "info" {
		t.Errorf("Level = %q, want info for a level-0 Security record", logon.Level)
	}
	if logon.User != `CORP\yesveer` {
		t.Errorf("User = %q, want CORP\\yesveer from the event data", logon.User)
	}
	want := time.Date(2026, time.September, 27, 10, 3, 1, 482913000, time.UTC)
	if !logon.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %s, want %s", logon.Timestamp, want)
	}

	crash := recs[1]
	if crash.Level != "error" {
		t.Errorf("Level = %q, want error for level 2", crash.Level)
	}
	// No account name in the data, so the SID is the only identity available;
	// reporting nobody would be worse.
	if crash.User != "S-1-5-21-1111-2222-3333-1001" {
		t.Errorf("User = %q, want the SID fallback", crash.User)
	}
	if crash.Raw == "" {
		t.Error("an error event lost its structured data")
	}
	if !strings.Contains(crash.Raw, "ExceptionCode=c0000005") {
		t.Errorf("Raw = %q, want the event data keys", crash.Raw)
	}
}

// Windows renders messages for a dialog box: CRLF endings and a block of
// trailing blank lines. Shipping those verbatim bloats every record and, in
// NDJSON, risks one entry being read as several.
func TestWinMessageIsCleaned(t *testing.T) {
	recs, _ := parseSample(t, sampleWinEvents, false, 0)
	msg := recs[0].Message

	if strings.Contains(msg, "\r") {
		t.Error("carriage returns survived into the record")
	}
	if strings.HasSuffix(msg, "\n") || strings.HasPrefix(msg, "\n") {
		t.Errorf("message was not trimmed: %q", msg)
	}
	if !strings.HasPrefix(msg, "An account was successfully logged on.") {
		t.Errorf("message content was damaged: %q", msg)
	}
}

// An event whose provider is no longer installed renders with an empty
// message. Those arrive precisely when somebody is investigating an uninstalled
// program, so falling back to the structured data is what makes them usable.
func TestEventWithNoRenderedMessageFallsBackToEventData(t *testing.T) {
	doc := `<Events><Event><System><Provider Name="OldApp"/><EventID>7</EventID><Level>3</Level>` +
		`<TimeCreated SystemTime="2026-09-27T11:00:00.0000000Z"/><EventRecordID>5</EventRecordID>` +
		`<Channel>Application</Channel></System>` +
		`<EventData><Data Name="Param1">disk full</Data><Data Name="Param2">C:</Data></EventData>` +
		`<RenderingInfo Culture="en-US"><Message></Message></RenderingInfo></Event></Events>`

	recs, _ := parseSample(t, doc, false, 0)
	if len(recs) != 1 {
		t.Fatalf("parsed %d events, want 1", len(recs))
	}
	if recs[0].Message == "" {
		t.Fatal("the event arrived with no message at all")
	}
	for _, want := range []string{"Param1=disk full", "Param2=C:"} {
		if !strings.Contains(recs[0].Message, want) {
			t.Errorf("message %q is missing %q", recs[0].Message, want)
		}
	}
	if recs[0].Level != "warning" {
		t.Errorf("Level = %q, want warning for level 3", recs[0].Level)
	}
}

// The cursor must advance past an event that cannot be turned into a record.
// If it did not, that event would be re-read on every poll forever and nothing
// behind it would ever ship.
func TestCursorAdvancesPastAnUnusableEvent(t *testing.T) {
	doc := `<Events><Event><System><EventID>1</EventID><Level>4</Level>` +
		`<TimeCreated SystemTime="not-a-time"/><EventRecordID>9001</EventRecordID>` +
		`<Channel>System</Channel></System><RenderingInfo><Message>x</Message></RenderingInfo></Event></Events>`

	recs, highest := parseSample(t, doc, false, 0)
	if len(recs) != 0 {
		t.Errorf("an event with an unparseable time was kept: %+v", recs)
	}
	if highest != 9001 {
		t.Errorf("highest = %d, want 9001 — otherwise this channel stalls forever", highest)
	}
}

func TestParseWinEventsRespectsTheLimit(t *testing.T) {
	recs, _ := parseSample(t, sampleWinEvents, false, 1)
	if len(recs) != 1 {
		t.Fatalf("returned %d events for a limit of 1", len(recs))
	}
}

// A query killed mid-write leaves an unterminated document. The events already
// written are still good and must not be thrown away with the broken tail.
func TestTruncatedDocumentKeepsTheEventsBeforeTheCut(t *testing.T) {
	cut := sampleWinEvents[:strings.LastIndex(sampleWinEvents, "<Event xmlns")+400]

	recs, highest, err := parseWinEvents(strings.NewReader(cut), false, 0)
	if err == nil {
		t.Log("decoder tolerated the truncation")
	}
	if len(recs) != 1 {
		t.Fatalf("kept %d events from a truncated document, want the 1 complete one", len(recs))
	}
	if highest != 884412 {
		t.Errorf("highest = %d, want 884412", highest)
	}
}

func TestWinLevelMapping(t *testing.T) {
	cases := []struct {
		n        int
		rendered string
		want     string
	}{
		{1, "Critical", "critical"},
		{2, "Error", "error"},
		{3, "Warning", "warning"},
		{4, "Information", "info"},
		{5, "Verbose", "debug"},
		{0, "Information", "info"},
		{0, "", "info"},
		{0, "Error", "error"}, // level 0 but the provider rendered a severity
	}
	for _, c := range cases {
		if got := winLevel(c.n, c.rendered); got != c.want {
			t.Errorf("winLevel(%d, %q) = %q, want %q", c.n, c.rendered, got, c.want)
		}
	}
}

func TestUserFromEventIgnoresThePlaceholderAccount(t *testing.T) {
	var e winEvent
	e.System.Security.UserID = "S-1-5-18"
	e.EventData = []winDatum{
		{Name: "TargetUserName", Value: "-"},
		{Name: "TargetDomainName", Value: "-"},
	}
	// Windows writes "-" for "no account". Reporting a user literally named "-"
	// would be worse than falling back to the SID.
	if got := userFromEvent(e); got != "S-1-5-18" {
		t.Errorf("userFromEvent = %q, want the SID", got)
	}
}
