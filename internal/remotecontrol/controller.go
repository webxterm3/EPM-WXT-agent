// Package remotecontrol is the agent daemon's half of the remote-control
// feature.
//
// The daemon does none of the actual work: capture, input and the consent
// prompt all belong to the session helper, which runs inside the user's
// desktop (see the ipc package for why). What lives here is the bridge — it
// launches the helper on demand, relays the backend's commands to it, and
// reports state back up the existing gRPC stream.
package remotecontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Yesveer/wxt-agent/internal/remotecontrol/helperbin"
	"github.com/Yesveer/wxt-agent/internal/remotecontrol/ipc"
	"go.uber.org/zap"
)

// Message types exchanged with the backend over the terminal-input channel,
// alongside the existing port_* and vscode_* families.
const (
	MsgStart  = "rc_start"
	MsgStop   = "rc_stop"
	MsgStatus = "rc_status"

	// MsgState is the reply to any of the above, and is also pushed
	// unsolicited whenever the helper's state changes — so the portal learns
	// that the user clicked Deny without having to poll for it.
	MsgState = "rc_state"
)

// helperStartTimeout bounds launching the helper and waiting for it to attach.
const helperStartTimeout = 35 * time.Second

// Controller owns the link to the session helper.
type Controller struct {
	logger     *zap.Logger
	helperPath string

	// permWatch is set while a permission watch is running, so a burst of
	// refused sessions starts one watcher rather than one per attempt.
	permWatch atomic.Bool

	// permReport is told whenever the macOS privacy state is observed.
	//
	// The agent publishes it for the menu bar item to read, because the menu
	// bar must never ask for itself: macOS attributes a privacy request to the
	// responsible process at the head of the chain, so a menu bar item that
	// ran the check would put its own name in System Settings — a row that
	// grants nothing and cannot be removed programmatically.
	permReport atomic.Pointer[func(ok bool, note string)]

	// send delivers a message back to the backend on the given session.
	send func(sessionID string, data []byte) error

	mu sync.Mutex
	// host is nil until the first session; the helper is launched on demand
	// rather than at boot so that a machine nobody ever connects to never runs
	// a second process.
	host *ipc.Host
	// replyTo is the terminal session the backend is driving this from, kept
	// so unsolicited helper events can be routed back to the right place.
	replyTo string
}

// New creates a Controller. helperPath may be empty, in which case the helper
// is looked for next to the agent binary.
func New(helperPath string, logger *zap.Logger, send func(string, []byte) error) *Controller {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Controller{logger: logger, helperPath: helperPath, send: send}
}

// helperNames lists the filenames the session helper may have, most canonical
// first.
//
// The installers write the plain name, but the portal serves the helper with an
// architecture suffix — it has to, since one download URL per platform cannot
// be ambiguous about which binary it is. Somebody who follows the obvious path
// of curl-ing both files into one directory therefore ends up with
// "wxt-agent-session-amd64.exe" sitting next to "wxt-agent.exe", and looking
// only for the canonical name would reject a perfectly good install over a
// filename.
func helperNames() []string {
	if runtime.GOOS == "windows" {
		return []string{
			"wxt-agent-session.exe",
			"wxt-agent-session-" + runtime.GOARCH + ".exe",
		}
	}
	return []string{
		"wxt-agent-session",
		"wxt-agent-session-" + runtime.GOOS + "-" + runtime.GOARCH,
		// The macOS downloads are published as "...-macos-<arch>" rather than
		// "...-darwin-<arch>", matching how the portal labels them.
		"wxt-agent-session-macos-" + runtime.GOARCH,
	}
}

// defaultHelperDir is the directory the helper is expected in: the one holding
// the running agent. Deriving it avoids a config option that could drift out of
// step with the install layout.
func defaultHelperDir() string {
	// The application bundle first, on macOS, and the reason is not tidiness.
	//
	// macOS attributes a privacy request made by a binary inside a bundle to
	// the BUNDLE. A helper run from /usr/local/bin is its own unbundled
	// program, so System Settings lists it separately from the agent: two
	// rows and two switches for one product, and granting one of them does
	// nothing for the other. Run from inside wxt-agent.app there is a single
	// row, named and iconed like the app.
	//
	// Falls through to the agent's own directory when the bundle is not
	// installed — an agent enrolled from the command line still works, it just
	// shows the second row.
	if dir := bundleHelperDir(); dir != "" {
		return dir
	}

	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// CanonicalHelperName is the filename installers should write. Anything the
// lookup accepts gets renamed to this on install, so a machine ends up in one
// predictable state however the operator obtained the binary.
func CanonicalHelperName() string {
	if runtime.GOOS == "windows" {
		return "wxt-agent-session.exe"
	}
	return "wxt-agent-session"
}

// EnsureHelper returns a usable session helper in dir, extracting the copy
// embedded in this binary if none is already there.
//
// Extraction is what makes the agent a single download: operators used to have
// to fetch a second file, match its architecture to the agent's and keep the
// two together, and every one of those steps was a way to end up with an
// install that looked complete and failed only when somebody tried to connect.
func EnsureHelper(dir string) (string, error) {
	// When a helper is embedded it always wins, even if one is already on
	// disk. Returning the existing file unconditionally left a self-updated
	// agent paired with the PREVIOUS version's helper — two halves of the same
	// feature speaking different versions of the IPC protocol, with nothing to
	// suggest an upgrade had only half happened. Extract is a no-op when the
	// bytes already match, so this costs nothing in the normal case.
	// An application bundle is READ ONLY, whatever is embedded here.
	//
	// Writing a single byte inside a signed .app breaks its seal, and macOS
	// then refuses to open it with "the application is damaged and can't be
	// opened. You should move it to the Trash." The user is told their
	// security agent is damaged, by the operating system, and offered the bin.
	//
	// It took exactly one condition to get there: the helper the bundle ships
	// and the helper the agent carries embedded are both correct and both
	// signed, but codesign is not deterministic — the same input signed twice
	// produces different bytes — so the byte comparison below always said
	// "different" and always rewrote the bundle copy on the first session.
	//
	// The bundle's own copy is the right one anyway: an upgrade replaces the
	// whole bundle, so what is in there matches the agent that shipped with
	// it. Pairing with a slightly older helper, in the case where it does not,
	// is a version mismatch the IPC handshake already reports. A destroyed
	// application is not recoverable by anything.
	if insideAppBundle(dir) {
		if existing, err := FindHelper(dir); err == nil {
			return existing, nil
		}
		// No helper in the bundle: fall through and install one somewhere
		// writable rather than refusing to work at all.
		dir = writableHelperDir()
	}

	if helperAvailable() {
		path := filepath.Join(dir, CanonicalHelperName())
		if _, err := helperExtract(path); err != nil {
			// Fall back to whatever is on disk: an older helper that works is
			// better than no session at all.
			if existing, ferr := FindHelper(dir); ferr == nil {
				return existing, nil
			}
			return "", fmt.Errorf("could not install the session helper to %s: %w", path, err)
		}
		return path, nil
	}

	// No embedded copy — this is a build made without the Makefile's inject
	// step, so fall back to whatever was installed alongside.
	return FindHelper(dir)
}

// FindHelper returns the first candidate that exists in dir, or an error naming
// every path it tried — a bare "not found" leaves the operator guessing which
// of several plausible locations and spellings was actually wrong.
func FindHelper(dir string) (string, error) {
	var tried []string
	for _, name := range helperNames() {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		tried = append(tried, p)
	}
	return "", fmt.Errorf(
		"the session helper is missing — remote control needs it next to the agent.\n"+
			"This agent is %s/%s, so it needs the %s build.\n"+
			"Looked for:\n  %s\n"+
			"Download it from the portal's Packages page into %s",
		runtime.GOOS, runtime.GOARCH, runtime.GOARCH,
		strings.Join(tried, "\n  "), dir)
}

// HandleMessage dispatches one backend message. It is safe to call from the
// gRPC receive loop: everything that could block runs on its own goroutine.
func (c *Controller) HandleMessage(sessionID string, msg map[string]any) {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case MsgStart:
		go c.handleStart(sessionID, msg)
	case MsgStop:
		go c.handleStop(sessionID)
	case MsgStatus:
		go c.handleStatus(sessionID)
	}
}

// Handles reports whether msgType belongs to this controller.
func Handles(msgType string) bool {
	switch msgType {
	case MsgStart, MsgStop, MsgStatus:
		return true
	}
	return false
}

func (c *Controller) handleStart(sessionID string, msg map[string]any) {
	c.mu.Lock()
	c.replyTo = sessionID
	c.mu.Unlock()

	host, err := c.ensureHelper(sessionID)
	if err != nil {
		c.logger.Warn("Could not start the session helper", zap.Error(err))
		c.reply(sessionID, ipc.Response{State: ipc.StateError, Error: err.Error()})
		return
	}

	// The VNC password is generated here, per session, and never reused. It is
	// a second line of defence only: the RFB port is loopback-bound and
	// reachable solely through the agent's authenticated tunnel.
	password, err := sessionPassword()
	if err != nil {
		c.reply(sessionID, ipc.Response{State: ipc.StateError, Error: err.Error()})
		return
	}

	arg := ipc.StartArg{
		AdminName:          stringField(msg, "admin_name"),
		Reason:             stringField(msg, "reason"),
		Password:           password,
		ConsentTimeoutSec:  intField(msg, "consent_timeout_sec"),
		ViewOnly:           boolField(msg, "view_only"),
		IdleTimeoutMinutes: intField(msg, "idle_timeout_minutes"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), helperStartTimeout)
	defer cancel()

	resp, err := host.Call(ctx, ipc.OpStart, arg)
	if err != nil {
		state := ipc.StateError
		if resp != nil && resp.State != "" {
			state = resp.State
		}

		// A refusal can also surface here, when the helper fails before it
		// gets as far as asking for consent. The usual path is the event
		// handler below — see onHelperEvent.
		if isPermissionDenied(err) {
			c.logger.Info("Session refused for want of a macOS permission; watching for it to be granted")
			c.dropHelper()
			c.watchForPermissions()
		}

		c.reply(sessionID, ipc.Response{State: state, Error: err.Error()})
		return
	}

	// The password travels back so the backend can hand it to guacd. It is
	// deliberately not logged anywhere.
	out := *resp
	out.Error = ""
	c.replyWithPassword(sessionID, out, password)
}

func (c *Controller) handleStop(sessionID string) {
	c.mu.Lock()
	host := c.host
	c.mu.Unlock()

	if host == nil {
		c.reply(sessionID, ipc.Response{State: ipc.StateIdle})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := host.Call(ctx, ipc.OpStop, nil); err != nil {
		c.logger.Warn("Stopping the session failed", zap.Error(err))
	}
	c.reply(sessionID, ipc.Response{State: ipc.StateIdle})
}

func (c *Controller) handleStatus(sessionID string) {
	c.mu.Lock()
	host := c.host
	c.mu.Unlock()

	if host == nil || !host.Connected() {
		c.reply(sessionID, ipc.Response{State: ipc.StateIdle})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := host.Call(ctx, ipc.OpStatus, nil)
	if err != nil {
		c.reply(sessionID, ipc.Response{State: ipc.StateError, Error: err.Error()})
		return
	}
	c.reply(sessionID, *resp)
}

// ensureHelper starts the helper if it is not already attached.
func (c *Controller) ensureHelper(sessionID string) (*ipc.Host, error) {
	c.mu.Lock()
	if c.host != nil && c.host.Connected() {
		h := c.host
		c.mu.Unlock()
		return h, nil
	}
	// A host that exists but is not connected is stale — the user logged out,
	// or the helper crashed. Drop it and launch a fresh one rather than
	// sending commands into a dead socket.
	if c.host != nil {
		_ = c.host.Close()
		c.host = nil
	}
	c.mu.Unlock()

	// Resolved per session rather than at startup, so a helper that went
	// missing can be restored without restarting the agent.
	helperPath := c.helperPath
	if helperPath == "" {
		var err error
		helperPath, err = EnsureHelper(defaultHelperDir())
		if err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(helperPath); err != nil {
		return nil, fmt.Errorf("the session helper is missing at %s", helperPath)
	}

	host := ipc.NewHost(helperPath, c.logger)
	host.OnEvent(func(e ipc.Event) { c.onHelperEvent(e) })

	ctx, cancel := context.WithTimeout(context.Background(), helperStartTimeout)
	defer cancel()

	if err := host.Start(ctx); err != nil {
		_ = host.Close()
		return nil, err
	}

	c.mu.Lock()
	c.host = host
	c.mu.Unlock()

	c.logger.Info("Session helper ready", zap.String("path", helperPath))
	return host, nil
}

// sessionInFlight reports whether a helper is currently connected.
//
// Used by the permission watch to keep out of the way: its check launches a
// helper of its own, and doing that while a session is being set up is a race
// for no benefit.
func (c *Controller) sessionInFlight() bool {
	c.mu.Lock()
	host := c.host
	c.mu.Unlock()
	return host != nil && host.Connected()
}

// dropHelper closes the current helper so the next session starts a new one.
func (c *Controller) dropHelper() {
	c.mu.Lock()
	host := c.host
	c.host = nil
	c.mu.Unlock()

	if host != nil {
		_ = host.Close()
	}
}

// isPermissionDenied reports whether an error is macOS refusing a TCC grant.
//
// Matched on text because the error crosses a process boundary as a string:
// the helper is a separate program, so the sentinel errors cannot survive the
// trip. Markers rather than whole messages, since those carry a binary path
// that differs per machine.
func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"denied screen capture", "denied input control", "declined tccs",
		"screen recording", "accessibility",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// onHelperEvent forwards a helper event to the backend.
func (c *Controller) onHelperEvent(e ipc.Event) {
	if e.Kind == "keepalive" {
		return
	}

	// A permission refusal arrives HERE, not as an error from OpStart.
	//
	// The helper answers the start request with "awaiting consent" and only
	// discovers it has no Screen Recording or Accessibility grant afterwards,
	// once consent is given and it tries to capture — by which time the call
	// has long returned successfully. So the check in handleStart, which looks
	// at that call's error, never saw a refusal: the helper was never dropped,
	// the watch never started, and the agent never restarted itself. The log
	// showed session after session failing with nothing reacting to it.
	if e.State == ipc.StateError && isPermissionDenied(errors.New(e.Message)) {
		c.logger.Info("Session refused for want of a macOS permission; watching for it to be granted")
		c.reportPermissions(false, e.Message)
		// Reported to the backend first — dropping the helper closes the
		// connection this event arrived on, and the portal still needs to be
		// told why the session failed.
		defer func() {
			c.dropHelper()
			c.watchForPermissions()
		}()
	}

	c.mu.Lock()
	sessionID := c.replyTo
	c.mu.Unlock()
	if sessionID == "" {
		return
	}

	payload := map[string]any{
		"type":       MsgState,
		"event":      e.Kind,
		"state":      string(e.State),
		"session_id": e.SessionID,
	}
	if e.Message != "" {
		payload["message"] = e.Message
	}
	if e.Viewer != "" {
		payload["viewer"] = e.Viewer
	}
	// Without these the backend never learns where to point guacd.
	if e.Port != 0 {
		payload["port"] = e.Port
	}
	if e.Width != 0 {
		payload["width"] = e.Width
		payload["height"] = e.Height
	}
	c.sendJSON(sessionID, payload)
}

func (c *Controller) reply(sessionID string, resp ipc.Response) {
	c.replyWithPassword(sessionID, resp, "")
}

func (c *Controller) replyWithPassword(sessionID string, resp ipc.Response, password string) {
	payload := map[string]any{
		"type":       MsgState,
		"state":      string(resp.State),
		"session_id": resp.SessionID,
	}
	if resp.Error != "" {
		payload["error"] = resp.Error
	}
	if resp.Port != 0 {
		payload["port"] = resp.Port
	}
	if resp.Width != 0 {
		payload["width"] = resp.Width
		payload["height"] = resp.Height
	}
	if resp.Viewer != "" {
		payload["viewer"] = resp.Viewer
	}
	if !resp.StartedAt.IsZero() {
		payload["started_at"] = resp.StartedAt.UTC().Format(time.RFC3339)
	}
	if password != "" {
		payload["password"] = password
	}
	c.sendJSON(sessionID, payload)
}

func (c *Controller) sendJSON(sessionID string, payload map[string]any) {
	if c.send == nil {
		return
	}
	b, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("Could not encode a remote-control message", zap.Error(err))
		return
	}
	if err := c.send(sessionID, b); err != nil {
		c.logger.Debug("Could not deliver a remote-control message", zap.Error(err))
	}
}

// Close stops the helper if one is running.
func (c *Controller) Close() error {
	c.mu.Lock()
	host := c.host
	c.host = nil
	c.mu.Unlock()

	if host == nil {
		return nil
	}
	return host.Close()
}

// sessionPassword generates the per-session VNC password. RFB only uses the
// first 8 bytes of a password, so generating more would be theatre.
func sessionPassword() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating the session password: %w", err)
	}
	return hex.EncodeToString(b[:]), nil // 8 characters
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func boolField(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// intField reads a number. JSON decoding produces float64 for every number, so
// an int assertion would silently yield zero.
func intField(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// SetPermissionReporter registers the callback told about macOS privacy state.
//
// Optional: nothing here depends on it, and an agent that never sets one works
// exactly as before. It exists so the state can be published once, by the one
// process that is allowed to ask, and read by everything else.
func (c *Controller) SetPermissionReporter(fn func(ok bool, note string)) {
	c.permReport.Store(&fn)
}

// reportPermissions passes an observation on, if anybody is listening.
func (c *Controller) reportPermissions(ok bool, note string) {
	if fn := c.permReport.Load(); fn != nil && *fn != nil {
		(*fn)(ok, note)
	}
}

// insideAppBundle reports whether a path sits within a macOS .app.
//
// Used to keep the agent from writing where a code signature has sealed
// everything: anything under Contents/ is covered by the bundle's seal, so a
// write there is the difference between a working product and an application
// the operating system calls damaged.
func insideAppBundle(path string) bool {
	for dir := filepath.Clean(path); dir != "/" && dir != "." && dir != ""; dir = filepath.Dir(dir) {
		if strings.EqualFold(filepath.Ext(dir), ".app") {
			return true
		}
	}
	return false
}

// writableHelperDir is somewhere the agent may install a helper.
//
// The agent's own directory, which is /usr/local/bin for a normal install —
// never inside the application bundle.
func writableHelperDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Dir(exe)
	if insideAppBundle(dir) {
		// The agent itself now runs from inside the bundle, so its own
		// directory is no help. Fall back to the install directory the
		// installers use.
		return fallbackHelperDir
	}
	return dir
}

// helperAvailable and helperExtract are indirected so a test can stand in an
// embedded helper.
//
// Without a seam here the one behaviour that matters most — that the agent
// never writes inside a signed application bundle — is untestable: a test
// binary carries no embedded helper, so the extract path is never reached and
// a test passes whether or not the guard exists. That is exactly what happened,
// and the bug it hid told users their security agent was damaged.
//
// The same shape as ipc.Host's launch field, for the same reason.
var (
	helperAvailable = helperbin.Available
	helperExtract   = helperbin.Extract
)
