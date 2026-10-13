package executor

import (
	"bytes"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/osuser"
)

// defaultShell is the shell commands are run through. Linux and macOS both
// have it; on Windows this executor path is not used.
const defaultShell = "/bin/bash"

// Executor handles command execution as a specific Linux user
type Executor struct {
	username   string
	uid        int
	gid        int
	homeDir    string
	shell      string
	allowSudo  bool
	logger     *zap.Logger
	userExists bool
}

// New creates an executor for the given username.
//
// It never creates the account. The accounts on a managed endpoint are the
// company's — made by its directory, its MDM or its IT team — and a monitoring
// agent inventing a new local login on every machine it lands on is a change
// nobody asked for and nobody can see. This product enables and disables access
// for accounts that already exist; it does not provision them.
//
// homeDir is the working directory recorded at configure time. It is a
// fallback, used only when the account cannot be resolved locally.
func New(username string, allowSudo bool, homeDir string, logger *zap.Logger) (*Executor, error) {
	e := &Executor{
		username:  username,
		allowSudo: allowSudo,
		logger:    logger,
	}

	u, err := osuser.Lookup(username)
	if err != nil {
		// Not fatal, deliberately. Nothing the endpoint actually does needs
		// this account resolved: input and capture run in the user's own
		// session, and on Windows setUserCredentials is a no-op. Refusing to
		// start over a name turns a cosmetic detail into "the machine never
		// appears in the portal".
		e.logger.Warn("Could not resolve the configured account; continuing without it",
			zap.String("username", username),
			zap.String("consequence", "command execution as this user is unavailable; registration, monitoring and remote access are not affected"),
			zap.Error(err))
		e.userExists = false
		e.homeDir = homeDir
		e.shell = defaultShell
		return e, nil
	}

	e.userExists = true
	e.logger.Info("Using existing account", zap.String("username", username))

	// Parse UID and GID. These are POSIX ids; on Windows os/user returns SIDs,
	// which do not parse, and nothing on that platform reads them.
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	e.uid = uid
	e.gid = gid
	e.homeDir = u.HomeDir
	if e.homeDir == "" {
		e.homeDir = homeDir
	}
	e.shell = defaultShell

	return e, nil
}

// Execute runs a command as the configured user
func (e *Executor) Execute(command string, env map[string]string) (*ExecutionResult, error) {
	e.logger.Info("Executing command",
		zap.String("command", command),
		zap.String("user", e.username),
		zap.String("workdir", e.homeDir),
	)

	// Create command. This IS the agent's core purpose — running a command the
	// authenticated (mTLS) backend sent — not an injection bug; e.shell is
	// always the fixed literal "/bin/bash", never derived from `command`.
	cmd := exec.Command(e.shell, "-c", command) // #nosec G204

	// Set working directory to user's home
	cmd.Dir = e.homeDir

	// Set up environment
	cmd.Env = e.buildEnvironment(env)

	// Set user credentials (platform-specific)
	e.setUserCredentials(cmd)

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute
	err := cmd.Run()

	// Determine exit code
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	result := &ExecutionResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: int32(exitCode),
	}

	e.logger.Info("Command executed",
		zap.String("command", command),
		zap.Int32("exit_code", result.ExitCode),
		zap.Int("stdout_len", len(result.Stdout)),
		zap.Int("stderr_len", len(result.Stderr)),
	)

	return result, nil
}

// buildEnvironment builds environment variables for command execution
func (e *Executor) buildEnvironment(extraEnv map[string]string) []string {
	env := []string{
		"HOME=" + e.homeDir,
		"USER=" + e.username,
		"LOGNAME=" + e.username,
		"SHELL=" + e.shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}

	// Add extra environment variables
	for k, v := range extraEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	return env
}

// GetUserInfo returns information about the executor's user
func (e *Executor) GetUserInfo() UserInfo {
	return UserInfo{
		Username:  e.username,
		UID:       e.uid,
		GID:       e.gid,
		HomeDir:   e.homeDir,
		Shell:     e.shell,
		AllowSudo: e.allowSudo,
	}
}

// UserInfo contains information about a user
type UserInfo struct {
	Username  string
	UID       int
	GID       int
	HomeDir   string
	Shell     string
	AllowSudo bool
}

// ExecutionResult contains the result of a command execution
type ExecutionResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int32
}

// CheckSudoAccess checks if the user has sudo access
func CheckSudoAccess(username string) bool {
	u, err := osuser.Lookup(username)
	if err != nil {
		return false
	}

	gids, err := u.GroupIds()
	if err != nil {
		return false
	}

	// Check if user is in sudo or wheel group
	for _, gid := range gids {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		if g.Name == "sudo" || g.Name == "wheel" {
			return true
		}
	}

	return false
}

// ValidateSudoAccess validates that the user has sudo access if required
func ValidateSudoAccess(username string) error {
	if !CheckSudoAccess(username) {
		return fmt.Errorf("user '%s' is not in sudo group. Add user to sudo group: sudo usermod -aG sudo %s. User must be in sudo group", username, username)
	}
	return nil
}
