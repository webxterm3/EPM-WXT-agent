package logship

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Bookmarks persist each source's read position across agent restarts.
//
// Without this, an agent restart either re-reads everything — filling the
// archive with duplicates of the same events — or skips to "now" and loses
// whatever happened while it was stopped. Both make the archive untrustworthy
// for the one question it exists to answer, and the second is worse because
// the gap is invisible.
type Bookmarks struct {
	path string

	mu  sync.Mutex
	pos map[string]Position
}

// LoadBookmarks reads the bookmark file, returning an empty set when it does
// not exist yet.
func LoadBookmarks(path string) (*Bookmarks, error) {
	b := &Bookmarks{path: path, pos: map[string]Position{}}

	data, err := os.ReadFile(path) // #nosec G304 -- path is the agent's own state directory
	if os.IsNotExist(err) {
		return b, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading bookmarks: %w", err)
	}
	if len(data) == 0 {
		return b, nil
	}

	if err := json.Unmarshal(data, &b.pos); err != nil {
		// A corrupt bookmark file must not stop collection. Starting over
		// risks re-shipping, which is recoverable; refusing to run is not.
		return b, fmt.Errorf("bookmarks were unreadable and have been reset: %w", err)
	}
	return b, nil
}

// Get returns the stored position for a source, or one starting at fallback.
func (b *Bookmarks) Get(source string, fallback Position) Position {
	b.mu.Lock()
	defer b.mu.Unlock()

	p, ok := b.pos[source]
	if !ok {
		return fallback
	}
	if p.Cursor == nil {
		p.Cursor = map[string]string{}
	}
	return p
}

// Save records a source's position and writes the file.
//
// It is called only after a batch has been handed over, so a crash mid-flight
// re-reads those records rather than dropping them. Duplicates are the
// tolerable failure here; gaps are not.
func (b *Bookmarks) Save(source string, p Position) error {
	b.mu.Lock()
	b.pos[source] = p
	snapshot, err := json.MarshalIndent(b.pos, "", "  ")
	b.mu.Unlock()
	if err != nil {
		return fmt.Errorf("encoding bookmarks: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(b.path), 0o755); err != nil { // #nosec G301
		return fmt.Errorf("creating the bookmark directory: %w", err)
	}

	// Write-and-rename: a half-written bookmark file read after a crash would
	// be worse than none, because it could decode as a plausible but wrong
	// position and silently skip records.
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, snapshot, 0o600); err != nil {
		return fmt.Errorf("writing bookmarks: %w", err)
	}
	if err := os.Rename(tmp, b.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing bookmarks: %w", err)
	}
	return nil
}
