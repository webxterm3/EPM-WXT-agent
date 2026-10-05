package logship

import (
	"sync"
	"time"
)

// Budget caps how much a machine may ship in a day.
//
// Collecting whole system logs is open-ended by nature: a machine that starts
// logging an error in a tight loop can produce gigabytes in an hour, and
// without a ceiling that lands as bandwidth on the user's connection and cost
// in the bucket before anybody notices. The budget makes the worst case
// bounded and, just as importantly, VISIBLE — a machine that hits it says so
// rather than quietly truncating.
type Budget struct {
	mu sync.Mutex

	limit int64 // bytes per day; zero means unlimited
	used  int64
	day   int   // year-day the counter belongs to
	drops int64 // records dropped since the last report

	now func() time.Time // injectable for tests
}

// NewBudget returns a budget of limitBytes per day. Zero or negative means no
// limit.
func NewBudget(limitBytes int64) *Budget {
	return &Budget{limit: limitBytes, now: time.Now}
}

// Allow reports whether n more bytes may be shipped, counting them when so.
func (b *Budget) Allow(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rollover()

	if b.limit <= 0 {
		b.used += n
		return true
	}
	if b.used+n > b.limit {
		b.drops++
		return false
	}
	b.used += n
	return true
}

// rollover resets the counter when the day changes. Called with the lock held.
func (b *Budget) rollover() {
	today := b.now().YearDay()
	if b.day != today {
		b.day = today
		b.used = 0
		b.drops = 0
	}
}

// Stats reports the day's usage so far.
func (b *Budget) Stats() (used, limit, dropped int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollover()
	return b.used, b.limit, b.drops
}

// Exhausted reports whether the day's budget is spent.
func (b *Budget) Exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollover()
	return b.limit > 0 && b.used >= b.limit
}
