package logship

import (
	"encoding/xml"
	"io"
	"strings"
	"time"
)

// This file holds the parsing and channel logic for the Windows Event Log. Like
// unified.go it carries no build tag, so the fiddly part is testable from a Mac
// instead of only on the one platform where it runs.

// winSourceName is the Record.Source value and the bookmark key.
const winSourceName = "windows-eventlog"

// DefaultWindowsChannels is what the agent collects unless told otherwise.
//
// Windows exposes roughly a thousand channels, nearly all of them empty or
// pure driver telemetry. Querying them all every poll would cost far more than
// it returns, so this is the set where things an operator actually
// investigates get written: the three classic logs, plus the operational logs
// covering sign-in, remote access, script execution, defence, and app crashes.
var DefaultWindowsChannels = []string{
	"Security",
	"System",
	"Application",
	"Setup",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
	"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-WinRM/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-AppLocker/EXE and DLL",
}

// winEvent mirrors the RenderedXml form of one event.
type winEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
		Security      struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
		Execution struct {
			ProcessID string `xml:"ProcessID,attr"`
		} `xml:"Execution"`
	} `xml:"System"`

	RenderingInfo struct {
		Message  string `xml:"Message"`
		Level    string `xml:"Level"`
		Provider string `xml:"Provider"`
	} `xml:"RenderingInfo"`

	EventData []winDatum `xml:"EventData>Data"`
}

type winDatum struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// winLevel maps the numeric level to the shared severity vocabulary.
//
// Level 0 means "undefined", which the Security channel uses for every single
// audit record — treating it as unknown would leave the most important channel
// on the machine unfilterable.
func winLevel(n int, rendered string) string {
	switch n {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	case 4:
		return "info"
	case 5:
		return "debug"
	}
	switch strings.ToLower(strings.TrimSpace(rendered)) {
	case "critical":
		return "critical"
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "verbose":
		return "debug"
	case "information", "":
		return "info"
	default:
		return strings.ToLower(rendered)
	}
}

// eventDataMessage builds a readable line from the structured data. It serves
// both as the message fallback and as Record.Raw — the event XML itself is not
// kept, because it is mostly schema boilerplate and at this volume the
// boilerplate would be the bulk of the bill.
//
// It is the fallback for events whose provider metadata is missing — an
// uninstalled application, a channel from a since-removed driver. Without it
// those records arrive with an empty message and are useless, which is
// precisely when somebody is looking for them.
func eventDataMessage(data []winDatum) string {
	var b strings.Builder
	for _, d := range data {
		v := strings.TrimSpace(d.Value)
		if v == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		if d.Name != "" {
			b.WriteString(d.Name)
			b.WriteString("=")
		}
		b.WriteString(v)
	}
	return b.String()
}

// cleanWinMessage normalises the rendered text.
//
// Windows messages are formatted for a GUI dialog: CRLF line endings and a
// block of trailing blank lines. Left alone those bloat every record and turn
// one log entry into many lines in anything that reads NDJSON loosely.
func cleanWinMessage(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		out = append(out, strings.TrimRight(l, " \t"))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// userFromEvent picks the best available account for the record.
//
// The rendered Security/@UserID is a SID, which is stable but unreadable; the
// Security channel carries the account name in EventData instead. Preferring
// the name keeps the common case legible and falls back to the SID rather than
// reporting nobody.
func userFromEvent(e winEvent) string {
	var domain, name string
	for _, d := range e.EventData {
		switch d.Name {
		case "TargetUserName", "SubjectUserName", "User":
			if name == "" {
				name = strings.TrimSpace(d.Value)
			}
		case "TargetDomainName", "SubjectDomainName":
			if domain == "" {
				domain = strings.TrimSpace(d.Value)
			}
		}
	}
	// "-" is how Windows spells "no account" in these fields.
	if name == "" || name == "-" {
		return e.System.Security.UserID
	}
	if domain != "" && domain != "-" {
		return domain + "\\" + name
	}
	return name
}

// recordFromWinEvent normalises one event.
func recordFromWinEvent(e winEvent, keepRaw bool) (Record, bool) {
	ts, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
	if err != nil {
		// Unorderable, so unusable — see parseUnifiedLine for why that is
		// worse than dropping it.
		return Record{}, false
	}

	msg := cleanWinMessage(e.RenderingInfo.Message)
	if msg == "" {
		msg = eventDataMessage(e.EventData)
	}

	provider := e.RenderingInfo.Provider
	if provider == "" {
		provider = e.System.Provider.Name
	}

	rec := Record{
		Timestamp: ts.UTC(),
		Source:    winSourceName,
		Channel:   e.System.Channel,
		Level:     winLevel(e.System.Level, e.RenderingInfo.Level),
		EventID:   e.System.EventID,
		Process:   provider,
		User:      userFromEvent(e),
		Message:   truncate(msg, maxMessageBytes),
	}

	// Built here rather than by the caller so the "errors always keep their
	// detail" rule cannot be bypassed by a caller that has raw capture off.
	if keepRaw || rec.Level == "error" || rec.Level == "critical" {
		rec.Raw = truncate(eventDataMessage(e.EventData), maxMessageBytes)
	}
	return rec, true
}

// parseWinEvents streams events out of a `wevtutil qe /f:RenderedXml` document,
// returning the records and the highest EventRecordID seen.
//
// It decodes incrementally rather than unmarshalling the whole document: a busy
// Security channel produces tens of megabytes per query, and holding all of it
// in memory to then walk it is the kind of thing that makes an agent the
// biggest process on a user's laptop.
func parseWinEvents(r io.Reader, keepRaw bool, limit int) ([]Record, uint64, error) {
	dec := xml.NewDecoder(r)
	// Event messages carry text in whatever code page the provider used; a
	// strict decoder would abort the whole batch on one bad byte.
	dec.Strict = false
	dec.CharsetReader = passthroughCharset

	var (
		records []Record
		highest uint64
	)

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return records, highest, nil
		}
		if err != nil {
			// Return what was parsed: a document truncated by a killed process
			// or a malformed tail should still yield the events before it.
			return records, highest, err
		}

		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}

		var e winEvent
		if err := dec.DecodeElement(&e, &start); err != nil {
			// One unreadable event costs that event, not the batch.
			continue
		}

		if e.System.EventRecordID > highest {
			highest = e.System.EventRecordID
		}

		if rec, ok := recordFromWinEvent(e, keepRaw); ok {
			records = append(records, rec)
		}

		if limit > 0 && len(records) >= limit {
			return records, highest, nil
		}
	}
}

// passthroughCharset accepts any declared encoding rather than failing.
//
// wevtutil declares UTF-8 and emits UTF-8, but providers embed message text
// verbatim. Refusing an unexpected declaration would mean collecting nothing
// from that channel at all, which is a far worse outcome than mojibake in one
// field.
func passthroughCharset(_ string, input io.Reader) (io.Reader, error) {
	return input, nil
}
