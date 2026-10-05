package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Uploader hands a compressed batch to the backend. The agent supplies one
// backed by its pinned-CA HTTP client.
type Uploader interface {
	// Upload sends one gzipped NDJSON batch. It must be safe to retry: a
	// timeout that actually succeeded server-side produces duplicates, which
	// is the acceptable failure here.
	Upload(ctx context.Context, gzipped []byte, records int) error
}

// Config controls collection.
type Config struct {
	// Interval is how often sources are polled.
	Interval time.Duration

	// BatchRecords caps records per upload.
	BatchRecords int

	// DailyBudgetBytes caps compressed bytes shipped per day. Zero means no
	// limit, which is only sensible on a machine somebody is watching.
	DailyBudgetBytes int64

	// Backfill bounds how far back the first run reads. Without it a machine
	// with months of history ships all of it the moment the agent starts.
	Backfill time.Duration

	// StatePath is where read positions are persisted.
	StatePath string
}

// DefaultConfig is tuned to be useful without being ruinous: a poll often
// enough to be current, batches small enough to retry cheaply, and a budget
// that bounds a pathological machine.
func DefaultConfig(statePath string) Config {
	return Config{
		Interval:         30 * time.Second,
		BatchRecords:     2000,
		DailyBudgetBytes: 256 << 20, // 256 MiB compressed
		Backfill:         24 * time.Hour,
		StatePath:        statePath,
	}
}

// Shipper polls sources and uploads what they produce.
type Shipper struct {
	cfg    Config
	src    []Source
	up     Uploader
	marks  *Bookmarks
	budget *Budget
	logger *zap.Logger

	// reported tracks the last budget report so the log carries one line a day
	// rather than one per poll.
	reportedDay int
}

// New builds a Shipper. It returns an error only when state cannot be loaded
// at all; a corrupt bookmark file is logged and started over from.
func New(cfg Config, sources []Source, up Uploader, logger *zap.Logger) (*Shipper, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.BatchRecords <= 0 {
		cfg.BatchRecords = 2000
	}
	if cfg.Backfill <= 0 {
		cfg.Backfill = 24 * time.Hour
	}

	marks, err := LoadBookmarks(cfg.StatePath)
	if err != nil {
		logger.Warn("Log shipping: bookmarks reset", zap.Error(err))
	}
	if marks == nil {
		return nil, fmt.Errorf("log shipping: could not load state from %s", cfg.StatePath)
	}

	return &Shipper{
		cfg:    cfg,
		src:    sources,
		up:     up,
		marks:  marks,
		budget: NewBudget(cfg.DailyBudgetBytes),
		logger: logger,
	}, nil
}

// Run polls until ctx is cancelled.
func (s *Shipper) Run(ctx context.Context) {
	if len(s.src) == 0 {
		s.logger.Info("Log shipping: no sources on this platform — disabled")
		return
	}

	names := make([]string, 0, len(s.src))
	for _, src := range s.src {
		names = append(names, src.Name())
	}
	s.logger.Info("Log shipping started",
		zap.Strings("sources", names),
		zap.Duration("interval", s.cfg.Interval),
		zap.Int64("daily_budget_bytes", s.cfg.DailyBudgetBytes))

	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()

	s.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			for _, src := range s.src {
				_ = src.Close()
			}
			s.logger.Info("Log shipping stopped")
			return
		case <-t.C:
			s.poll(ctx)
		}
	}
}

func (s *Shipper) poll(ctx context.Context) {
	if s.budget.Exhausted() {
		s.reportBudgetOnce()
		return
	}

	for _, src := range s.src {
		if ctx.Err() != nil {
			return
		}
		s.drain(ctx, src)
	}
}

// drain reads and ships from one source until it has nothing more, the batch
// budget is spent, or an error stops it.
func (s *Shipper) drain(ctx context.Context, src Source) {
	// A source that keeps producing must not monopolise the poll and starve
	// the others, so each gets a bounded number of batches per round.
	const maxBatchesPerPoll = 10

	for i := 0; i < maxBatchesPerPoll; i++ {
		if ctx.Err() != nil || s.budget.Exhausted() {
			return
		}

		from := s.marks.Get(src.Name(), NewPosition(time.Now().Add(-s.cfg.Backfill)))

		records, next, err := src.Read(ctx, from, s.cfg.BatchRecords)
		if err != nil {
			s.logger.Warn("Log shipping: read failed",
				zap.String("source", src.Name()), zap.Error(err))
			return
		}
		if len(records) == 0 {
			return
		}

		payload, err := encodeBatch(records)
		if err != nil {
			s.logger.Warn("Log shipping: encode failed",
				zap.String("source", src.Name()), zap.Error(err))
			return
		}

		if !s.budget.Allow(int64(len(payload))) {
			s.reportBudgetOnce()
			return
		}

		if err := s.up.Upload(ctx, payload, len(records)); err != nil {
			var permanent *PermanentError
			if !errors.As(err, &permanent) {
				// The bookmark is deliberately NOT advanced: the next poll
				// re-reads these records. Shipping them twice is recoverable,
				// losing them is not.
				s.logger.Warn("Log shipping: upload failed, will retry",
					zap.String("source", src.Name()),
					zap.Int("records", len(records)), zap.Error(err))
				return
			}

			// A batch the server will never accept is skipped instead. Holding
			// the bookmark for it would resend the same rejected batch every
			// poll forever and block every record behind it — losing this one
			// batch loudly is far better than silently losing all of them.
			s.logger.Error("Log shipping: batch rejected, skipping it",
				zap.String("source", src.Name()),
				zap.Int("records", len(records)),
				zap.Int("status", permanent.Status),
				zap.String("detail", permanent.Body))
		}

		if err := s.marks.Save(src.Name(), next); err != nil {
			// Saving failed after a successful upload: the next poll re-reads
			// and re-ships the same records. Duplicates, not loss.
			s.logger.Warn("Log shipping: could not save position — records may be re-sent",
				zap.String("source", src.Name()), zap.Error(err))
			return
		}

		s.logger.Debug("Log shipping: batch sent",
			zap.String("source", src.Name()),
			zap.Int("records", len(records)),
			zap.Int("bytes", len(payload)))

		// A short batch means the source is caught up.
		if len(records) < s.cfg.BatchRecords {
			return
		}
	}
}

// reportBudgetOnce logs the budget state at most once a day, so an exhausted
// machine says so without repeating it every poll.
func (s *Shipper) reportBudgetOnce() {
	day := time.Now().YearDay()
	if s.reportedDay == day {
		return
	}
	s.reportedDay = day

	used, limit, dropped := s.budget.Stats()
	s.logger.Warn("Log shipping: daily budget reached — collection paused until tomorrow",
		zap.Int64("used_bytes", used),
		zap.Int64("limit_bytes", limit),
		zap.Int64("batches_dropped", dropped))
}

// encodeBatch renders records as gzipped NDJSON.
//
// NDJSON because it streams: a consumer can process a batch line by line
// without holding it all in memory, and a truncated upload still yields every
// complete record before the cut rather than failing to parse entirely.
func encodeBatch(records []Record) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			return nil, fmt.Errorf("encoding record %d: %w", i, err)
		}
	}

	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
