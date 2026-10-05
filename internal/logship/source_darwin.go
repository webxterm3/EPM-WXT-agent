//go:build darwin

package logship

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// logShowPath is the absolute path to the log tool. It is not looked up on
// PATH: this runs as root, and resolving a privileged helper through an
// inherited PATH is how a daemon ends up executing somebody else's binary.
const logShowPath = "/usr/bin/log"

// startOverlap is subtracted from the cursor before each read.
//
// `log show --start` takes whole seconds, so asking for the exact cursor time
// would drop everything that happened later in that same second. Reading a
// little extra and discarding the overlap by mach timestamp trades a few
// duplicate lines read for a guarantee of no gap.
const startOverlap = 2 * time.Second

// UnifiedLogSource reads the macOS unified log.
//
// It shells out to `log show` rather than linking OSLog: the C API for reading
// the store is private, and the supported route is this tool. The cost is a
// process per batch, which at a 30-second poll is negligible next to what the
// captured data itself costs.
type UnifiedLogSource struct {
	// Predicate is an NSPredicate applied by `log show`. Empty means no
	// filtering beyond the level default below.
	Predicate string

	// IncludeInfoDebug turns on info- and debug-level records. It is off by
	// default because those are the bulk of the unified log by a wide margin
	// and are almost never what an investigation needs — leaving them on is
	// the difference between a manageable archive and an unaffordable one.
	IncludeInfoDebug bool

	// KeepRaw stores each entry's original JSON. Errors and faults keep theirs
	// regardless; this extends that to everything, roughly doubling volume.
	KeepRaw bool
}

// NewUnifiedLogSource returns the macOS system log source.
func NewUnifiedLogSource() *UnifiedLogSource { return &UnifiedLogSource{} }

func (s *UnifiedLogSource) Name() string { return unifiedSourceName }

// Close is a no-op: each read owns its own process.
func (s *UnifiedLogSource) Close() error { return nil }

func (s *UnifiedLogSource) Read(ctx context.Context, from Position, limit int) ([]Record, Position, error) {
	cursor := decodeUnifiedCursor(from)

	start := cursor.last
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	start = start.Add(-startOverlap)

	args := []string{
		"show",
		"--style", "ndjson",
		"--start", start.Local().Format("2006-01-02 15:04:05"),
	}
	if s.IncludeInfoDebug {
		args = append(args, "--info", "--debug")
	}
	if s.Predicate != "" {
		args = append(args, "--predicate", s.Predicate)
	}

	// The command is cancelled as soon as enough records are in hand, so a
	// backlog is drained in bounded batches instead of one unbounded read.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(runCtx, logShowPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, from, fmt.Errorf("log show: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, from, fmt.Errorf("starting log show: %w", err)
	}

	records := make([]Record, 0, limit)
	sc := bufio.NewScanner(stdout)
	// Unified log lines can be long; a line over the cap is skipped rather
	// than aborting the read, so one oversized entry costs one entry.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		rec, entry, ts, ok := parseUnifiedLine(sc.Bytes(), s.KeepRaw)
		if !ok || !cursor.isNew(entry, ts) {
			continue
		}

		records = append(records, rec)
		cursor.last = ts
		cursor.mach = entry.MachTimestamp
		if entry.BootUUID != "" {
			cursor.boot = entry.BootUUID
		}

		if len(records) >= limit {
			break
		}
	}
	scanErr := sc.Err()

	cancel()
	waitErr := cmd.Wait()

	// A kill is the normal way this read ends, so it is not an error. Anything
	// else with no records to show for it is reported, because a source that
	// fails silently looks exactly like a quiet machine.
	if len(records) == 0 && !isKilled(waitErr) && waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, from, fmt.Errorf("log show failed: %s", truncate(msg, 512))
	}
	if len(records) == 0 && scanErr != nil {
		return nil, from, fmt.Errorf("reading log show output: %w", scanErr)
	}

	return records, cursor.encode(from), nil
}

// isKilled reports whether the process ended because we cancelled it.
func isKilled(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// SIGKILL/SIGTERM surface here as a signal rather than a status.
		return exitErr.ProcessState.ExitCode() == -1
	}
	return false
}
