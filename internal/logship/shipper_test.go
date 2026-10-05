package logship

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeSource hands out a fixed set of records, advancing a numeric cursor.
type fakeSource struct {
	mu      sync.Mutex
	name    string
	records []Record
	reads   int
	err     error
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Close() error { return nil }

func (f *fakeSource) Read(_ context.Context, from Position, limit int) ([]Record, Position, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reads++
	if f.err != nil {
		return nil, from, f.err
	}

	start, _ := strconv.Atoi(from.Get("n"))
	if start >= len(f.records) {
		return nil, from, nil
	}
	end := start + limit
	if end > len(f.records) {
		end = len(f.records)
	}
	return f.records[start:end], from.Set("n", strconv.Itoa(end)), nil
}

func (f *fakeSource) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// fakeUploader captures batches and can be made to fail.
type fakeUploader struct {
	mu      sync.Mutex
	batches [][]Record
	bytes   int
	fail    error
}

func (u *fakeUploader) Upload(_ context.Context, gzipped []byte, _ int) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.fail != nil {
		return u.fail
	}
	recs, err := decodeBatch(gzipped)
	if err != nil {
		return err
	}
	u.batches = append(u.batches, recs)
	u.bytes += len(gzipped)
	return nil
}

func (u *fakeUploader) all() []Record {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []Record
	for _, b := range u.batches {
		out = append(out, b...)
	}
	return out
}

func (u *fakeUploader) setFail(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.fail = err
}

func decodeBatch(gzipped []byte) ([]Record, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var out []Record
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func makeRecords(n int) []Record {
	out := make([]Record, n)
	base := time.Date(2026, time.September, 27, 10, 0, 0, 0, time.UTC)
	for i := range out {
		out[i] = Record{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Source:    "test",
			Message:   "event " + strconv.Itoa(i),
		}
	}
	return out
}

func newShipper(t *testing.T, src Source, up Uploader, tune func(*Config)) *Shipper {
	t.Helper()
	cfg := DefaultConfig(filepath.Join(t.TempDir(), "bookmarks.json"))
	cfg.BatchRecords = 10
	if tune != nil {
		tune(&cfg)
	}
	s, err := New(cfg, []Source{src}, up, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestShipperSendsEveryRecordOnce(t *testing.T) {
	src := &fakeSource{name: "test", records: makeRecords(25)}
	up := &fakeUploader{}
	s := newShipper(t, src, up, nil)

	s.poll(context.Background())

	got := up.all()
	if len(got) != 25 {
		t.Fatalf("shipped %d records, want 25", len(got))
	}
	for i, r := range got {
		if want := "event " + strconv.Itoa(i); r.Message != want {
			t.Errorf("record %d = %q, want %q (order or duplication is wrong)", i, r.Message, want)
		}
	}
}

// A second poll with nothing new must ship nothing. Re-sending on every poll
// would multiply the archive by the poll rate.
func TestShipperDoesNotResendCaughtUpRecords(t *testing.T) {
	src := &fakeSource{name: "test", records: makeRecords(15)}
	up := &fakeUploader{}
	s := newShipper(t, src, up, nil)

	s.poll(context.Background())
	first := len(up.all())

	s.poll(context.Background())
	if got := len(up.all()); got != first {
		t.Errorf("a second poll shipped %d more records", got-first)
	}
}

// A failed upload must NOT advance the bookmark: the records have to be
// retried. Losing them is the one failure that makes the archive untrustworthy.
func TestFailedUploadIsRetriedNotDropped(t *testing.T) {
	src := &fakeSource{name: "test", records: makeRecords(10)}
	up := &fakeUploader{}
	up.setFail(errors.New("network down"))

	s := newShipper(t, src, up, nil)
	s.poll(context.Background())

	if n := len(up.all()); n != 0 {
		t.Fatalf("%d records recorded despite the upload failing", n)
	}

	up.setFail(nil)
	s.poll(context.Background())

	got := up.all()
	if len(got) != 10 {
		t.Fatalf("after recovery shipped %d records, want all 10", len(got))
	}
}

// Positions must survive a restart, or an agent restart either re-ships
// everything or skips whatever happened while it was down.
func TestBookmarksSurviveARestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "bookmarks.json")

	src1 := &fakeSource{name: "test", records: makeRecords(10)}
	up1 := &fakeUploader{}
	cfg := DefaultConfig(state)
	cfg.BatchRecords = 10
	s1, err := New(cfg, []Source{src1}, up1, nil)
	if err != nil {
		t.Fatal(err)
	}
	s1.poll(context.Background())
	if len(up1.all()) != 10 {
		t.Fatalf("first run shipped %d, want 10", len(up1.all()))
	}

	// A "restart": new shipper, same state file, same records available.
	src2 := &fakeSource{name: "test", records: makeRecords(10)}
	up2 := &fakeUploader{}
	s2, err := New(cfg, []Source{src2}, up2, nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.poll(context.Background())

	if n := len(up2.all()); n != 0 {
		t.Errorf("after restart re-shipped %d already-sent records", n)
	}
}

func TestCorruptBookmarksDoNotStopCollection(t *testing.T) {
	state := filepath.Join(t.TempDir(), "bookmarks.json")
	if err := os.WriteFile(state, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := &fakeSource{name: "test", records: makeRecords(5)}
	up := &fakeUploader{}
	cfg := DefaultConfig(state)
	cfg.BatchRecords = 10

	// Refusing to run because a state file is unreadable would be worse than
	// starting over: the machine would silently stop collecting entirely.
	s, err := New(cfg, []Source{src}, up, nil)
	if err != nil {
		t.Fatalf("New refused to start on a corrupt bookmark file: %v", err)
	}
	s.poll(context.Background())

	if len(up.all()) != 5 {
		t.Errorf("shipped %d records after a corrupt bookmark reset, want 5", len(up.all()))
	}
}

// The budget is what makes whole-system-log collection affordable. Without it
// a machine stuck in an error loop can ship gigabytes before anybody notices.
func TestBudgetStopsShipping(t *testing.T) {
	// Size the budget from a real encoded batch rather than a guessed constant,
	// so the test does not start passing or failing because compression got a
	// little better.
	oneBatch, err := encodeBatch(makeRecords(10))
	if err != nil {
		t.Fatal(err)
	}
	budget := int64(len(oneBatch)) * 2

	src := &fakeSource{name: "test", records: makeRecords(500)}
	up := &fakeUploader{}
	s := newShipper(t, src, up, func(c *Config) {
		c.BatchRecords = 10
		c.DailyBudgetBytes = budget
	})

	s.poll(context.Background())

	shipped := len(up.all())
	if shipped == 0 {
		t.Fatal("the budget blocked everything")
	}
	// Two batches fit; the third must be refused. Anything more means the
	// ceiling is not being enforced.
	if shipped > 20 {
		t.Errorf("shipped %d records on a two-batch budget", shipped)
	}
	if !s.budget.Exhausted() {
		t.Error("budget reports itself as not exhausted after being spent")
	}
}

// A source that keeps producing must not hold the poll forever: the others
// would never be read, and their records would age out of the OS log.
func TestOneSourceCannotStarveThePoll(t *testing.T) {
	busy := &fakeSource{name: "busy", records: makeRecords(5000)}
	quiet := &fakeSource{name: "quiet", records: makeRecords(3)}
	up := &fakeUploader{}

	cfg := DefaultConfig(filepath.Join(t.TempDir(), "bookmarks.json"))
	cfg.BatchRecords = 10
	s, err := New(cfg, []Source{busy, quiet}, up, nil)
	if err != nil {
		t.Fatal(err)
	}

	s.poll(context.Background())

	if quiet.readCount() == 0 {
		t.Fatal("the quiet source was never read — the busy one monopolised the poll")
	}
	var quietShipped int
	for _, r := range up.all() {
		if r.Source == "test" && r.Message == "event 0" {
			quietShipped++
		}
	}
	if quietShipped == 0 {
		t.Error("nothing from the quiet source was shipped")
	}
}

func TestBudgetResetsNextDay(t *testing.T) {
	b := NewBudget(100)
	day := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return day }

	if !b.Allow(100) {
		t.Fatal("the first allocation within the limit was refused")
	}
	if b.Allow(1) {
		t.Fatal("an allocation past the limit was allowed")
	}

	b.now = func() time.Time { return day.AddDate(0, 0, 1) }
	if !b.Allow(100) {
		t.Error("the budget did not reset on the next day")
	}
}

func TestUnlimitedBudgetNeverBlocks(t *testing.T) {
	b := NewBudget(0)
	for i := 0; i < 100; i++ {
		if !b.Allow(1 << 20) {
			t.Fatalf("an unlimited budget refused allocation %d", i)
		}
	}
	if b.Exhausted() {
		t.Error("an unlimited budget reported itself exhausted")
	}
}

func TestPositionSetDoesNotMutateTheOriginal(t *testing.T) {
	// A failed batch is retried from the ORIGINAL position, so Set must not
	// alter it — otherwise a retry would resume past the records that failed.
	orig := NewPosition(time.Now()).Set("n", "10")
	next := orig.Set("n", "20")

	if orig.Get("n") != "10" {
		t.Errorf("the original position changed to %q", orig.Get("n"))
	}
	if next.Get("n") != "20" {
		t.Errorf("the new position = %q, want 20", next.Get("n"))
	}
}

func TestEncodeBatchRoundTrips(t *testing.T) {
	records := makeRecords(3)
	records[1].Raw = `{"nested":"json with \"quotes\" and \nnewlines"}`

	payload, err := encodeBatch(records)
	if err != nil {
		t.Fatalf("encodeBatch: %v", err)
	}
	got, err := decodeBatch(payload)
	if err != nil {
		t.Fatalf("decodeBatch: %v", err)
	}
	if len(got) != len(records) {
		t.Fatalf("round-tripped %d records, want %d", len(got), len(records))
	}
	// Embedded newlines must not split a record: NDJSON is line-delimited, so
	// an unescaped one would turn one record into two unparseable halves.
	if got[1].Raw != records[1].Raw {
		t.Errorf("raw payload = %q, want %q", got[1].Raw, records[1].Raw)
	}
}
