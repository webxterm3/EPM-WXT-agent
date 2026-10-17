// Package appcontrol enforces the application-control policy on this machine.
//
// Until this package existed the policy pipeline was complete and inert:
// policies were authored, resolved, pushed and stored on the endpoint, and
// nothing ever consulted them. internal/apppolicy could answer "what does the
// policy say about this program"; nobody asked.
//
// Enforcement here is two mechanisms, deliberately both:
//
//	Launch prevention stops a blocked application from starting at all. It is
//	the one that matters, because it is the only one a user does not see fail.
//	Windows uses Image File Execution Options, which is the OS refusing the
//	launch; macOS withholds the execute bit from the bundle's main binary.
//	Both are reversible and neither deletes anybody's software.
//
//	Process termination closes what is already running, and catches whatever
//	launch prevention missed — an application started before the policy
//	arrived, or one reached by a path the lock did not cover.
//
// Neither is Endpoint Security (macOS) or WDAC (Windows). Those are the
// kernel-level answer, they cannot be bypassed by a knowledgeable user, and
// both need vendor entitlements this product does not yet hold. What is here
// is honest application control for a managed fleet, not an anti-tamper
// boundary against the machine's own administrator — and the distinction is
// stated in the portal rather than papered over.
//
// # Safety
//
// Everything in this package can stop somebody's computer working, so the
// guards are not incidental:
//
//   - Nothing happens unless the resolved policy is in enforce mode.
//   - Protected system paths are never touched, whatever a rule says.
//   - The agent never acts on its own binaries — an agent that blocks itself
//     cannot be told to stop.
//   - A pass that would block an implausible number of applications is
//     refused whole and reported, so one mis-saved rule cannot brick a fleet
//     before anybody reads the alert.
package appcontrol

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/appinventory"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// processPollInterval is how often running programs are checked.
//
// A blocked application that slips past launch prevention is visible to the
// user for up to this long, so it wants to be short; it is a read of the
// process table, which is cheap, so it can be. Three seconds is the point
// where the window is small enough not to be useful and the cost is still
// nothing.
const processPollInterval = 3 * time.Second

// reconcileInterval is how often installed software is re-examined and the
// locks brought in line with the policy.
//
// This is what makes "it was installed after the policy arrived" work, so it
// has to be far shorter than the daily inventory scan. It walks application
// directories without reading signatures, which is a readdir and some small
// plist reads.
const reconcileInterval = 2 * time.Minute

// reconcileTimeout bounds one pass, so a stalled filesystem cannot wedge the
// loop and leave the machine unpoliced indefinitely.
const reconcileTimeout = 2 * time.Minute

// maxBlockedPerPass is the blast-radius circuit breaker.
//
// A rule saved with criteria that match far more than intended — or a default
// action of block on a machine the author did not mean to lock down — would
// otherwise be applied to the whole machine in one pass, and the first anybody
// would hear of it is a user who cannot open anything. Past this count the
// pass is abandoned whole, nothing is locked, and the refusal is reported.
//
// It is a deliberate ceiling on an allow-list deployment too: blocking
// hundreds of applications at once is a thing an operator may genuinely want,
// and they will have to do it knowing this fired.
const maxBlockedPerPass = 50

// eventQueueLimit bounds the unsent-event buffer so a machine that is offline
// while a noisy rule fires cannot grow the agent's memory without limit.
const eventQueueLimit = 500

// repeatEventGap suppresses a second report about the same application.
//
// A blocked application that relaunches itself is normal — a login item, a
// crash-restarting helper — and would otherwise produce an event every poll,
// which is three a second of identical rows nobody can read past.
const repeatEventGap = 5 * time.Minute

// Mechanisms, reported with each event so an operator can tell what actually
// happened rather than only that something did.
const (
	MechanismTerminate = "terminate"
	MechanismLock      = "launch-lock"
	MechanismUnlock    = "launch-unlock"
	MechanismRefused   = "refused"

	// MechanismQuarantine: the application was moved off the machine, into a
	// directory only the agent writes to. A move, never a delete — see
	// quarantine.go for why that distinction is the whole safety story.
	MechanismQuarantine = "quarantine"
	// MechanismRestore: a quarantined application was put back where it was.
	MechanismRestore = "restore"
)

// Outcomes.
const (
	OutcomeApplied = "applied"
	OutcomeFailed  = "failed"
	OutcomeSkipped = "skipped"
)

// Event is one thing the enforcer did, or declined to do, on this machine.
type Event struct {
	At        time.Time `json:"at"`
	Mechanism string    `json:"mechanism"`
	Outcome   string    `json:"outcome"`

	AppName  string `json:"app_name,omitempty"`
	Path     string `json:"path,omitempty"`
	BundleID string `json:"bundle_id,omitempty"`

	// Rule and Policy name what decided. Both empty means the policy's
	// default action applied rather than any rule — which is worth being able
	// to tell apart when somebody asks why their software stopped working.
	Rule   string `json:"rule,omitempty"`
	Policy string `json:"policy,omitempty"`

	PID int `json:"pid,omitempty"`

	// Detail carries the reason for a failure or a refusal. Empty on success.
	Detail string `json:"detail,omitempty"`
}

// Target is one program the enforcer can make a decision about.
type Target struct {
	Name      string
	Publisher string
	BundleID  string

	// Path is the unit a user would call "the application": the .app bundle on
	// macOS, the executable on Windows. It is what a lock is applied to.
	Path string

	// ExePath is the binary that actually runs.
	ExePath string
}

func (t Target) program() apppolicy.Program {
	return apppolicy.Program{
		Name: t.Name, Publisher: t.Publisher,
		Path: t.Path, BundleID: t.BundleID,
	}
}

// key identifies a target across passes.
func (t Target) key() string {
	if t.Path != "" {
		return strings.ToLower(t.Path)
	}
	if t.BundleID != "" {
		return "bundle:" + strings.ToLower(t.BundleID)
	}
	return "name:" + strings.ToLower(t.Name)
}

// RunningProcess is one entry from the process table.
type RunningProcess struct {
	PID     int
	PPID    int
	ExePath string
}

// ProcessLister reads the process table. Platform-specific.
type ProcessLister interface {
	List(ctx context.Context) ([]RunningProcess, error)
}

// Killer ends a process.
type Killer interface {
	Kill(pid int) error
}

// Locker prevents and restores the launching of an application.
//
// Lock must be idempotent — it is called every reconcile pass for as long as
// the application stays blocked — and Unlock must restore exactly what Lock
// changed, because the alternative is software this product broke and did not
// put back.
type Locker interface {
	// Kind names the mechanism for reporting.
	Kind() string
	Lock(t Target) error
	Unlock(t Target) error
}

// Reporter receives what the enforcer did. The agent sends these to the
// backend; tests collect them.
type Reporter func(events []Event)

// Enforcer applies one machine's policy to the software on it.
type Enforcer struct {
	logger *zap.Logger

	// policy is read fresh every pass rather than captured, so a pushed change
	// takes effect on the next tick without restarting anything.
	policy func() *apppolicy.Effective

	procs     ProcessLister
	killer    Killer
	locker    Locker
	collector appinventory.Collector
	report    Reporter

	// now is indirected for tests.
	now func() time.Time

	state *lockState

	// stateDir is where the quarantine lives, beside the lock record.
	stateDir string

	mu sync.Mutex
	// index maps an application path to the richer record the last scan found,
	// so a decision about a running process can use the publisher and version
	// that the process table does not carry.
	index map[string]Target
	// lastEvent rate-limits repeat reports per application.
	lastEvent map[string]time.Time
	queue     []Event

	// kick asks for an out-of-band reconcile, coalesced to one.
	kick chan struct{}
}

// Options configures an Enforcer. Every field has a working default; tests
// override the ones they need.
type Options struct {
	Logger    *zap.Logger
	StateDir  string
	Policy    func() *apppolicy.Effective
	Report    Reporter
	Procs     ProcessLister
	Killer    Killer
	Locker    Locker
	Collector appinventory.Collector
	Now       func() time.Time
}

// New builds an enforcer. It never returns nil.
func New(opts Options) *Enforcer {
	e := &Enforcer{
		logger:    opts.Logger,
		policy:    opts.Policy,
		procs:     opts.Procs,
		killer:    opts.Killer,
		locker:    opts.Locker,
		collector: opts.Collector,
		report:    opts.Report,
		now:       opts.Now,
		index:     map[string]Target{},
		lastEvent: map[string]time.Time{},
		kick:      make(chan struct{}, 1),
	}
	if e.logger == nil {
		e.logger = zap.NewNop()
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.policy == nil {
		e.policy = func() *apppolicy.Effective { return nil }
	}
	if e.procs == nil {
		e.procs = platformProcessLister()
	}
	if e.killer == nil {
		e.killer = platformKiller()
	}
	if e.locker == nil {
		e.locker = platformLocker(e.logger)
	}
	if e.collector == nil {
		e.collector = enforcementCollector()
	}
	e.state = newLockState(opts.StateDir, e.logger)
	e.stateDir = opts.StateDir
	return e
}

// Kick asks for a reconcile now rather than at the next tick. It is called
// when a policy arrives and after an inventory scan, and coalesces: ten
// requests in a second cost one pass.
func (e *Enforcer) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Run drives both loops until the context ends.
func (e *Enforcer) Run(ctx context.Context) {
	e.logger.Info("Application control started",
		zap.String("launch_prevention", e.locker.Kind()),
		zap.Duration("process_poll", processPollInterval),
		zap.Duration("reconcile", reconcileInterval))

	go e.processLoop(ctx)
	go e.watchInstalls(ctx)
	e.reconcileLoop(ctx)
}

func (e *Enforcer) processLoop(ctx context.Context) {
	t := time.NewTicker(processPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.sweepProcesses(ctx)
		}
	}
}

func (e *Enforcer) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(reconcileInterval)
	defer t.Stop()

	e.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			// Leaving locks in place is deliberate. The agent stopping is not
			// an instruction to unblock the software it was told to block, and
			// an uninstall is what removes them — see Release.
			return
		case <-t.C:
			e.Reconcile(ctx)
		case <-e.kick:
			e.Reconcile(ctx)
		}
	}
}

// enforcing reports the policy in force, or nil when nothing should be acted
// on. Audit mode, and a machine that has never received a policy, both return
// nil: the whole package is a no-op in either state.
func (e *Enforcer) enforcing() *apppolicy.Effective {
	p := e.policy()
	if p == nil || p.Mode != apppolicy.ModeEnforce {
		return nil
	}
	return p
}

// sweepProcesses closes anything running that the policy blocks.
func (e *Enforcer) sweepProcesses(ctx context.Context) {
	pol := e.enforcing()
	if pol == nil {
		return
	}

	procs, err := e.procs.List(ctx)
	if err != nil {
		e.logger.Debug("Application control: could not read the process table", zap.Error(err))
		return
	}

	// Decisions are cached per application for this sweep: a browser is
	// dozens of processes under one bundle, and evaluating the policy once per
	// process would be the same answer dozens of times.
	seen := map[string]bool{}

	for _, p := range procs {
		if p.ExePath == "" || isProtectedPath(p.ExePath) || isOwnBinary(p.ExePath) {
			continue
		}
		t := e.resolve(p.ExePath)
		if t.Name == "" {
			continue
		}

		k := t.key()
		blocked, known := seen[k]
		if !known {
			d := pol.Evaluate(t.program())
			blocked = d.Action == apppolicy.ActionBlock
			seen[k] = blocked
			if blocked {
				// Recorded once per application per sweep, not once per
				// process, so a browser's thirty helpers are one line.
				e.recordBlocked(t, d, p.PID)
			}
		}
		if !blocked {
			continue
		}
		if err := e.killer.Kill(p.PID); err != nil {
			e.logger.Debug("Application control: could not stop a blocked process",
				zap.String("app", t.Name), zap.Int("pid", p.PID), zap.Error(err))
		}
	}
}

// recordBlocked queues the report for one blocked application, rate-limited.
func (e *Enforcer) recordBlocked(t Target, d apppolicy.Decision, pid int) {
	e.logger.Info("Application control: stopping a blocked application",
		zap.String("app", t.Name), zap.String("path", t.Path),
		zap.String("rule", d.Rule), zap.String("policy", d.PolicyName))

	e.emit(Event{
		Mechanism: MechanismTerminate, Outcome: OutcomeApplied,
		AppName: t.Name, Path: t.Path, BundleID: t.BundleID,
		Rule: d.Rule, Policy: d.PolicyName, PID: pid,
	})
}

// Reconcile brings launch prevention in line with the policy: everything
// blocked is locked, everything this agent locked and no longer blocks is
// restored.
func (e *Enforcer) Reconcile(ctx context.Context) {
	if e.collector == nil {
		return // no collector for this platform; nothing to reconcile against
	}
	pol := e.enforcing()

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	apps, err := e.collector.Collect(ctx)
	if err != nil && len(apps) == 0 {
		e.logger.Debug("Application control: could not list installed software", zap.Error(err))
		return
	}

	targets := make([]Target, 0, len(apps))
	index := make(map[string]Target, len(apps))
	for _, a := range apps {
		t := targetFromApp(a)
		if t.Name == "" {
			continue
		}
		targets = append(targets, t)
		index[indexKey(t.Path)] = t
		if t.ExePath != "" {
			index[indexKey(t.ExePath)] = t
		}
	}

	e.mu.Lock()
	e.index = index
	e.mu.Unlock()

	// With no policy in force nothing new is blocked, but anything this agent
	// locked under a previous policy must still be released — otherwise
	// switching a policy back to audit would leave the machine locked down
	// with nothing on the server saying so.
	var blocked []lockRecord
	if pol != nil {
		var ok bool
		blocked, ok = e.decideLocks(pol, targets)
		if !ok {
			// The circuit breaker fired and reported for itself. Nothing is
			// locked AND nothing is released: the existing state is the last
			// one anybody approved, and a refused pass is not evidence that it
			// should be undone.
			return
		}
	}

	e.applyLocks(blocked)
}

// decideLocks returns what should be locked, and whether the pass may proceed.
//
// The two are separate returns on purpose. "Nothing should be locked" and "this
// pass is refused" are opposite instructions — the first means release
// everything, the second means change nothing — and a single nil slice spelled
// them identically.
func (e *Enforcer) decideLocks(pol *apppolicy.Effective, targets []Target) ([]lockRecord, bool) {
	var out []lockRecord
	seen := make(map[string]bool, len(targets))

	for _, t := range targets {
		if t.Path == "" || isProtectedPath(t.Path) || isOwnBinary(t.Path) || isOwnBinary(t.ExePath) {
			continue
		}
		d := pol.Evaluate(t.program())
		if d.Action != apppolicy.ActionBlock {
			continue
		}
		out = append(out, lockRecord{
			Key: t.key(), Name: t.Name, Path: t.Path,
			ExePath: t.ExePath, BundleID: t.BundleID,
			Publisher: t.Publisher,
			Rule:      d.Rule, Policy: d.PolicyName,
			Quarantined: d.Remove,
		})
		seen[t.key()] = true
	}

	// Applications already in quarantine are carried forward.
	//
	// Without this the feature undoes itself on its own next pass: a
	// quarantined application has, by definition, left the inventory — it is
	// no longer where any collector looks — so it is absent from `targets`,
	// absent from `out`, and applyLocks reads that absence as "no longer
	// blocked" and puts it straight back. The move itself changes the watched
	// directory's modification time, so the install watcher fires and the
	// whole thing repeats, every few seconds, moving somebody's application
	// back and forth.
	//
	// They are re-judged rather than assumed: the record carries the fields a
	// rule can match on, so a policy that has genuinely stopped blocking the
	// application still releases it.
	// Applications already in quarantine are carried forward.
	//
	// Without this the feature undoes itself on its own next pass: a
	// quarantined application has, by definition, left the inventory — it is
	// no longer where any collector looks — so it is absent from `targets`,
	// absent from `out`, and applyLocks reads that absence as "no longer
	// blocked" and puts it straight back. The move itself changes the watched
	// directory's modification time, so the install watcher fires and the
	// whole thing repeats, every few seconds, moving somebody's application
	// back and forth.
	//
	// They are re-judged rather than assumed: the record carries the fields a
	// rule can match on, so a policy that has genuinely stopped blocking the
	// application still releases it.
	for _, held := range e.state.all() {
		if !held.Quarantined || seen[held.Key] {
			continue
		}
		d := pol.Evaluate(apppolicy.Program{
			Name: held.Name, Publisher: held.Publisher,
			Path: held.Path, BundleID: held.BundleID,
		})
		if d.Action == apppolicy.ActionBlock && d.Remove {
			out = append(out, held)
		}
	}

	if len(out) > maxBlockedPerPass {
		names := make([]string, 0, len(out))
		for _, r := range out {
			names = append(names, r.Name)
		}
		sort.Strings(names)
		if len(names) > 10 {
			names = names[:10]
		}
		detail := "this policy would block " + itoa(len(out)) +
			" applications on this machine, which is past the safety limit of " +
			itoa(maxBlockedPerPass) + "; nothing was blocked. First few: " +
			strings.Join(names, ", ")

		e.logger.Error("Application control: refusing to apply a policy with an implausible blast radius",
			zap.Int("would_block", len(out)), zap.Int("limit", maxBlockedPerPass),
			zap.Strings("sample", names))
		e.emit(Event{
			Mechanism: MechanismRefused, Outcome: OutcomeSkipped,
			Detail: detail,
		})
		return nil, false
	}
	return out, true
}

// applyLocks locks everything in want and releases everything previously
// locked that is not.
func (e *Enforcer) applyLocks(want []lockRecord) {
	held := e.state.all()

	wanted := make(map[string]lockRecord, len(want))
	for _, r := range want {
		wanted[r.Key] = r
	}

	for _, r := range want {
		if r.Quarantined {
			e.applyQuarantine(r, held)
			continue
		}
		if err := e.locker.Lock(targetOf(r)); err != nil {
			// Only reported the first time: a lock that cannot be applied
			// stays un-appliable, and repeating the failure every two minutes
			// buries everything else.
			if _, already := held[r.Key]; !already {
				e.logger.Warn("Application control: could not prevent an application from launching",
					zap.String("app", r.Name), zap.String("path", r.Path), zap.Error(err))
				e.emit(Event{
					Mechanism: MechanismLock, Outcome: OutcomeFailed,
					AppName: r.Name, Path: r.Path, BundleID: r.BundleID,
					Rule: r.Rule, Policy: r.Policy, Detail: err.Error(),
				})
			}
			continue
		}
		if _, already := held[r.Key]; already {
			continue
		}
		e.logger.Info("Application control: blocked an application from launching",
			zap.String("app", r.Name), zap.String("path", r.Path),
			zap.String("rule", r.Rule), zap.String("mechanism", e.locker.Kind()))
		e.emit(Event{
			Mechanism: MechanismLock, Outcome: OutcomeApplied,
			AppName: r.Name, Path: r.Path, BundleID: r.BundleID,
			Rule: r.Rule, Policy: r.Policy,
		})
		e.state.add(r)
	}

	for key, r := range held {
		if _, keep := wanted[key]; keep {
			continue
		}
		if r.Quarantined {
			e.releaseQuarantine(key, r)
			continue
		}
		if err := e.locker.Unlock(targetOf(r)); err != nil {
			e.logger.Warn("Application control: could not restore an application",
				zap.String("app", r.Name), zap.String("path", r.Path), zap.Error(err))
			e.emit(Event{
				Mechanism: MechanismUnlock, Outcome: OutcomeFailed,
				AppName: r.Name, Path: r.Path, Detail: err.Error(),
			})
			// The record is kept so the restore is retried next pass rather
			// than forgotten, which would leave the application broken with
			// nothing left that knows to fix it.
			continue
		}
		e.logger.Info("Application control: restored an application no longer blocked",
			zap.String("app", r.Name), zap.String("path", r.Path))
		e.emit(Event{
			Mechanism: MechanismUnlock, Outcome: OutcomeApplied,
			AppName: r.Name, Path: r.Path, BundleID: r.BundleID,
		})
		e.state.remove(key)
	}
}

// Release restores everything this agent has locked.
//
// Called by the uninstaller. Removing the agent must not leave software it
// disabled still disabled, with the only thing that knew how to undo it gone.
func (e *Enforcer) Release() {
	for key, r := range e.state.all() {
		if r.Quarantined {
			e.releaseQuarantine(key, r)
			continue
		}
		if err := e.locker.Unlock(targetOf(r)); err != nil {
			e.logger.Warn("Application control: could not restore an application on shutdown",
				zap.String("app", r.Name), zap.Error(err))
			continue
		}
		e.state.remove(key)
	}
}

// resolve turns an executable path into the application it belongs to, using
// the last scan's record when there is one so publisher-based rules can match
// a running process.
func (e *Enforcer) resolve(exePath string) Target {
	base := applicationPathFor(exePath)

	e.mu.Lock()
	t, ok := e.index[indexKey(base)]
	if !ok {
		t, ok = e.index[indexKey(exePath)]
	}
	e.mu.Unlock()

	if ok {
		return t
	}
	// Not in the inventory: a command-line tool, something installed since the
	// last pass, or a bundle outside the search roots. It still gets a
	// decision — on the fields that are actually known — rather than a pass,
	// because "we had not scanned it yet" is not a reason to run it.
	return Target{
		Name:    displayNameFor(base),
		Path:    base,
		ExePath: exePath,
	}
}

func (e *Enforcer) emit(ev Event) {
	ev.At = e.now()

	if ev.Outcome == OutcomeApplied || ev.Mechanism == MechanismTerminate {
		k := ev.Mechanism + "|" + ev.Path + "|" + ev.AppName
		e.mu.Lock()
		last, seen := e.lastEvent[k]
		if seen && ev.At.Sub(last) < repeatEventGap {
			e.mu.Unlock()
			return
		}
		e.lastEvent[k] = ev.At
		e.mu.Unlock()
	}

	e.mu.Lock()
	if len(e.queue) >= eventQueueLimit {
		// Drop the oldest. The newest events describe what is happening now,
		// which is what somebody looking at this will want.
		e.queue = e.queue[1:]
	}
	e.queue = append(e.queue, ev)
	e.mu.Unlock()
}

// Drain removes and returns the queued events. The caller sends them; anything
// it cannot send is lost rather than retried, because these are a record of
// what happened and not a command anybody is waiting on.
func (e *Enforcer) Drain() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.queue
	e.queue = nil
	return out
}

func targetFromApp(a appinventory.Application) Target {
	path := a.InstallPath
	if path == "" {
		path = a.ExePath
	}
	return Target{
		Name: a.Name, Publisher: a.Publisher, BundleID: a.BundleID,
		Path: path, ExePath: a.ExePath,
	}
}

func targetOf(r lockRecord) Target {
	return Target{
		Name: r.Name, Publisher: r.Publisher,
		Path: r.Path, ExePath: r.ExePath, BundleID: r.BundleID,
	}
}

// indexKey normalises a path for lookup: separators and case vary between what
// the process table reports and what a scan recorded.
func indexKey(p string) string {
	return strings.ToLower(strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/"))
}

// displayNameFor is the fallback name for something not in the inventory.
func displayNameFor(p string) string {
	base := filepath.Base(p)
	base = strings.TrimSuffix(base, ".app")
	base = strings.TrimSuffix(base, ".exe")
	return base
}

// itoa avoids pulling strconv in for two call sites in an error string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Mechanism names how this platform prevents launches, for the activity
// report. An operator reading "blocked" needs to know whether that means the
// OS refused it or the agent closed it afterwards.
func (e *Enforcer) Mechanism() string { return e.locker.Kind() }

// HeldCount reports how many applications this agent is currently preventing
// from launching. Used by the uninstaller, which has to say what it is about
// to put back before it does it.
func (e *Enforcer) HeldCount() int { return len(e.state.all()) }

// applyQuarantine moves one blocked application off the machine.
//
// Separate from the lock path because the two fail differently and are undone
// differently: a lock that cannot be applied leaves the application working,
// while a quarantine that half-succeeds would leave it missing. The move is
// atomic — os.Rename — so there is no half-way state to reason about.
func (e *Enforcer) applyQuarantine(r lockRecord, held map[string]lockRecord) {
	_, already := held[r.Key]

	dst, err := quarantine(e.stateDir, targetOf(r))
	if err != nil {
		// Always reported, never suppressed.
		//
		// The suppression that used to live here keyed on "is this record
		// already held", which is true for every pass after the first — so the
		// one case that matters most, an application that REAPPEARED at its
		// original path after being quarantined (somebody reinstalled it past
		// the block), was reported exactly never. The operator saw a policy
		// enforcing and a machine running the software anyway.
		//
		// emit() already rate-limits identical events to one per five minutes,
		// which is the right place for that decision, so repetition is bounded
		// without any of it being invisible.
		e.logger.Warn("Application control: could not move a blocked application aside",
			zap.String("app", r.Name), zap.String("path", r.Path), zap.Error(err))
		e.emit(Event{
			Mechanism: MechanismQuarantine, Outcome: OutcomeFailed,
			AppName: r.Name, Path: r.Path, BundleID: r.BundleID,
			Rule: r.Rule, Policy: r.Policy, Detail: err.Error(),
		})
		return
	}
	if already {
		return // it is already put away; nothing to say
	}

	if dst == "" {
		// Nothing was installed at that path. The record is still kept, so a
		// later install of the same application is caught by the next pass
		// rather than treated as new.
		e.state.add(r)
		return
	}

	e.logger.Info("Application control: moved a blocked application off the machine",
		zap.String("app", r.Name), zap.String("from", r.Path), zap.String("to", dst),
		zap.String("rule", r.Rule),
		zap.String("note", "moved, not deleted — it is restored if the policy changes"))
	e.emit(Event{
		Mechanism: MechanismQuarantine, Outcome: OutcomeApplied,
		AppName: r.Name, Path: r.Path, BundleID: r.BundleID,
		Rule: r.Rule, Policy: r.Policy,
	})
	e.state.add(r)
}

// releaseQuarantine puts an application back once it is no longer blocked.
func (e *Enforcer) releaseQuarantine(key string, r lockRecord) {
	if err := release(e.stateDir, r.Path); err != nil {
		e.logger.Warn("Application control: could not restore a quarantined application",
			zap.String("app", r.Name), zap.String("path", r.Path), zap.Error(err))
		e.emit(Event{
			Mechanism: MechanismRestore, Outcome: OutcomeFailed,
			AppName: r.Name, Path: r.Path, Detail: err.Error(),
		})
		// The record is kept so the restore is retried rather than forgotten,
		// which would leave the application missing with nothing left that
		// knows where it went.
		return
	}

	e.logger.Info("Application control: restored an application that is no longer blocked",
		zap.String("app", r.Name), zap.String("path", r.Path))
	e.emit(Event{
		Mechanism: MechanismRestore, Outcome: OutcomeApplied,
		AppName: r.Name, Path: r.Path, BundleID: r.BundleID,
	})
	e.state.remove(key)
}
