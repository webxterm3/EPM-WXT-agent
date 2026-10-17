//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Yesveer/wxt-agent/internal/agent"
	"github.com/Yesveer/wxt-agent/internal/config"
	"github.com/Yesveer/wxt-agent/internal/remotecontrol"
	"github.com/Yesveer/wxt-agent/internal/traybin"
)

// macOS install paths. The agent keeps its config and certs where the Linux
// build does — /etc/vsay — rather than moving to /Library/Application Support,
// so that one set of paths works across both Unix platforms and the existing
// cert-handling code needs no per-OS branching.
const (
	// The label is shared with the self-update restart path — see
	// internal/agent/serviceids.go. Duplicating it is how the two drifted
	// apart before, leaving updates that installed but never took effect.
	macLaunchDaemonLabel = agent.LaunchDaemonLabel
	macLaunchDaemonPlist = "/Library/LaunchDaemons/" + agent.LaunchDaemonLabel + ".plist"
	macConfigPath        = "/etc/vsay/agent.yaml"
	macLogPath           = "/var/log/vsay/agent.log"
	macInstallDir        = "/usr/local/bin"
	// The menu bar item: a per-user LaunchAgent, installed machine-wide so it
	// starts for whoever logs in rather than only for whoever installed it.
	macMenuBarBinary = "/usr/local/bin/wxt-agent-menubar"
	macLaunchAgent   = "/Library/LaunchAgents/" + agent.LaunchAgentLabel + ".plist"
)

// runConfigureDarwin configures the agent on macOS.
//
// It exists because the Linux flow cannot run here at all: that path calls
// useradd and getent to provision a login account, and neither command exists
// on macOS. More importantly nothing needs provisioning — the daemon runs as
// root under launchd, and the part that touches the user's desktop is the
// session helper, which launchd starts in their own GUI session on demand. So
// this flow creates no accounts and asks for no --linux-user.
func runConfigureDarwin(p configureParams) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("configure must be run with sudo")
	}
	if p.Token == "" || p.Tenant == "" || p.Org == "" || p.Project == "" || p.User == "" || p.Host == "" {
		return fmt.Errorf("missing required flags: token, tenant, org, project, user and host are required")
	}

	fmt.Println("Configuring wxt-agent for macOS...")

	// Install the session helper alongside the agent, under the canonical name
	// whatever the download was called. Leaving it in ~/Downloads would look
	// like a successful install right up until an admin tries to connect — to
	// somebody's live desktop, with a user waiting — so it is worth doing here.
	if err := installSessionHelper(); err != nil {
		fmt.Printf("Warning: %v\n", err)
		fmt.Println("  Remote control will not work until the helper sits next to the agent.")
		fmt.Println("  Download it from the portal's Packages page and re-run configure.")
	}

	grpcURL := p.APIHost
	if grpcURL == "" {
		grpcURL = extractGRPCURL(p.Host)
		fmt.Printf("✓ Using default gRPC address: %s (extracted from --host)\n", grpcURL)
	} else {
		fmt.Printf("✓ Using custom gRPC address: %s\n", grpcURL)
	}

	_ = os.MkdirAll("/etc/vsay", 0755) // #nosec G301 -- readable by local tooling, same as the Linux layout
	_ = os.MkdirAll("/etc/vsay/certs", 0750)
	_ = os.MkdirAll("/var/log/vsay", 0755) // #nosec G301

	caCertFile, caFingerprint, err := fetchAndSaveCA(p.Host)
	if err != nil {
		fmt.Printf("Warning: could not pin CA cert: %v\n", err)
		fmt.Println("  Agent will use the system CA pool for server verification")
	} else if caFingerprint != "" {
		fmt.Println("✓ CA cert pinned — fingerprint (verify out-of-band):")
		fmt.Printf("  SHA256: %s\n", caFingerprint)
		if err := os.WriteFile("/etc/vsay/certs/ca-fingerprint.txt", []byte(caFingerprint), 0644); err != nil { // #nosec G306 -- a fingerprint is meant to be compared and shared
			fmt.Printf("Warning: could not persist CA fingerprint: %v\n", err)
		}
	}

	if err := fetchSignedClientCert(p.Host, p.Token); err != nil {
		return fmt.Errorf("failed to get a signed client cert from the backend: %w", err)
	}
	fmt.Println("✓ Client cert signed by the backend CA (ECDSA P-256)")

	cfg := &config.Config{
		Agent: config.AgentConfig{
			Name: p.MachineName,
			Metadata: map[string]string{
				// Tells the portal this machine offers live remote control
				// rather than a terminal.
				"platform": "macos",
			},
		},
		Server: config.ServerConfig{
			Host:       p.Host,
			GRPCURL:    grpcURL,
			APIHost:    p.APIHost,
			TLS:        true,
			TokenHash:  p.Token,
			CACertFile: caCertFile,
		},
		Tunnel: config.TunnelConfig{
			URL:          p.TunnelURL,
			Enabled:      p.TunnelURL != "",
			PollInterval: "10s",
		},
		// The console user is recorded even though macOS needs no account
		// provisioning: the web terminal opens a PTY as this user, and without
		// it the agent would try to spawn a shell with no username, no home
		// and no shell path.
		LinuxUser:  consoleUserConfig(),
		Tenant:     config.TenantConfig{ID: p.Tenant},
		Org:        config.OrgConfig{ID: p.Org},
		Project:    config.ProjectConfig{ID: p.Project},
		PortalUser: config.PortalUserConfig{Email: p.User},
		Logging: config.LoggingConfig{
			Level:      "info",
			File:       macLogPath,
			MaxSizeMB:  100,
			MaxBackups: 5,
		},
		Status: "pending_approval",
	}

	// Encrypted with a key derived from IOPlatformUUID, so the file is only
	// decryptable on this Mac.
	if err := config.SaveEncrypted(cfg, macConfigPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Println("✓ Configuration saved (encrypted) to", macConfigPath)

	if err := setupLaunchDaemon(); err != nil {
		return fmt.Errorf("failed to install the launchd service: %w", err)
	}
	fmt.Println("✓ Agent daemon installed and started")

	if err := setupMenuBarAgent(); err != nil {
		// Cosmetic. The agent works perfectly without a menu bar icon, and an
		// enrolment that otherwise succeeded must not be reported as failed
		// because an icon could not be installed.
		fmt.Printf("Warning: could not install the menu bar item: %v\n", err)
	} else {
		fmt.Println("✓ Menu bar item installed")
	}
	fmt.Println("✓ Agent will start automatically on boot")

	fmt.Println("")
	fmt.Println("One more step — macOS will not grant these silently.")
	fmt.Println("Asking for them now so they appear in System Settings…")
	waitForSettingsPane()
	registerPermissionRows()
	fmt.Println("")
	fmt.Println("Remote control cannot capture the screen or move the mouse without both.")
	fmt.Println("")
	fmt.Printf("Check status: sudo launchctl print system/%s\n", macLaunchDaemonLabel)
	fmt.Printf("View logs:    tail -f %s\n", macLogPath)

	return nil
}

// consoleUserConfig describes whoever is logged in at the screen.
//
// macOS creates no account for the agent — unlike Linux, where configure
// provisions one — but the terminal feature still needs somebody to run a
// shell as. /dev/console is owned by the user at the display, which makes
// stat'ing it the simplest reliable way to identify them.
func consoleUserConfig() config.LinuxUserConfig {
	var cfg config.LinuxUserConfig

	fi, err := os.Stat("/dev/console")
	if err != nil {
		fmt.Printf("Warning: could not identify the console user: %v\n", err)
		return cfg
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return cfg
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		fmt.Printf("Warning: could not look up uid %d: %v\n", st.Uid, err)
		return cfg
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	cfg = config.LinuxUserConfig{
		Username: u.Username,
		UID:      uid,
		GID:      gid,
		HomeDir:  u.HomeDir,
		Shell:    loginShell(u.Username),
	}
	fmt.Printf("✓ Terminal sessions will run as %s (uid %d, shell %s)\n",
		cfg.Username, cfg.UID, cfg.Shell)
	return cfg
}

// loginShell reads the user's shell from the directory service, falling back to
// zsh — the macOS default since Catalina.
func loginShell(username string) string {
	const fallback = "/bin/zsh"

	out, err := exec.Command("/usr/bin/dscl", ".", "-read", "/Users/"+username, "UserShell").Output()
	if err != nil {
		return fallback
	}
	// Output is "UserShell: /bin/zsh".
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return fallback
	}
	shell := fields[len(fields)-1]
	if !strings.HasPrefix(shell, "/") {
		return fallback
	}
	return shell
}

// installSessionHelper copies the helper next to the agent under the canonical
// name. It accepts any of the names the portal publishes, so an operator who
// curl-ed "wxt-agent-session-macos-arm64" into the same folder does not have to
// know it needed renaming.
func installSessionHelper() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine the agent path: %w", err)
	}

	dst := filepath.Join(macInstallDir, remotecontrol.CanonicalHelperName())

	// With the application bundle present, the bundle's copy is the only one
	// that should exist.
	//
	// Both installers already delete the loose copy, with a comment explaining
	// why — and this function then put it straight back, six lines later in
	// the same script. A second copy of the helper at a second path is a
	// second privacy client: macOS lists it separately, under a blank icon,
	// and no amount of signing makes the two rows merge. It is also never
	// executed once the bundle is there, so it could only ever collect a grant
	// that does nothing.
	if remotecontrol.BundleHelperPath() != "" {
		removeLooseCopy(dst)
		fmt.Println("✓ Session helper: using the copy inside wxt-agent.app")
		return nil
	}

	// The agent carries the helper inside itself, so a normal install needs no
	// second download. A copy sitting next to the binary still wins, which is
	// what lets a developer test a helper they just built.
	if src, err := remotecontrol.FindHelper(filepath.Dir(exe)); err == nil && src != dst {
		if err := copyFile(src, dst, 0755); err != nil {
			return fmt.Errorf("could not install the session helper to %s: %w", dst, err)
		}
		fmt.Printf("✓ Session helper installed to %s\n", dst)
		return nil
	}

	if _, err := remotecontrol.EnsureHelper(macInstallDir); err != nil {
		return err
	}
	fmt.Printf("✓ Session helper installed to %s\n", dst)
	return nil
}

// setupLaunchDaemon writes the LaunchDaemon plist and (re)loads it.
func setupLaunchDaemon() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine the agent path: %w", err)
	}

	// Run from a fixed location rather than wherever configure happened to be
	// invoked from: launchd re-executes this path on every boot, and a binary
	// still sitting in ~/Downloads would break the moment it is tidied away.
	installedPath := filepath.Join(macInstallDir, "wxt-agent")
	if exePath != installedPath {
		if err := copyFile(exePath, installedPath, 0755); err != nil {
			return fmt.Errorf("could not install the agent to %s: %w", installedPath, err)
		}
		fmt.Printf("✓ Agent installed to %s\n", installedPath)
	}

	// launchd starts the BUNDLE's copy when there is one.
	//
	// This is what collapses the product to a single row in System Settings.
	// macOS attributes a privacy request to the responsible process — the
	// topmost launchd-started ancestor — and launchctl asuser does not reset
	// it, so whichever binary launchd started is what every session helper's
	// request is recorded against. Started from /usr/local/bin that is an
	// unbundled binary with a blank icon; started from inside wxt-agent.app it
	// is the application itself, which is the row people are told to switch
	// on. The /usr/local/bin copy stays for command-line use.
	runPath := runtimeAgentPath()
	if runPath != installedPath {
		fmt.Printf("✓ Daemon will run from %s\n", runPath)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>start</string>
		<string>--config</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, macLaunchDaemonLabel, runPath, macConfigPath, macLogPath, macLogPath)

	// LaunchDaemon plists must be owned by root and not group/world writable,
	// or launchd refuses to load them.
	if err := os.WriteFile(macLaunchDaemonPlist, []byte(plist), 0644); err != nil { // #nosec G306 -- launchd requires a world-readable plist
		return fmt.Errorf("could not write %s: %w", macLaunchDaemonPlist, err)
	}
	if err := os.Chown(macLaunchDaemonPlist, 0, 0); err != nil {
		return fmt.Errorf("could not set ownership on %s: %w", macLaunchDaemonPlist, err)
	}

	// Unload any previous instance first; bootstrap fails outright if the
	// label is already loaded, which is the normal case when reconfiguring.
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+macLaunchDaemonLabel).Run()

	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", macLaunchDaemonPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap failed: %w\n%s", err, out)
	}
	if out, err := exec.Command("/bin/launchctl", "enable", "system/"+macLaunchDaemonLabel).CombinedOutput(); err != nil {
		// Non-fatal: bootstrap already started it, enable only affects whether
		// a disabled label is allowed to run.
		fmt.Printf("Warning: launchctl enable: %v\n%s", err, out)
	}
	return nil
}

// copyFile copies src to dst, replacing dst if it exists.
func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src) // #nosec G304 -- src is this process's own executable path
	if err != nil {
		return err
	}
	// Remove first: writing over a running binary gives "text file busy",
	// whereas unlinking leaves the running image alone and creates a new file.
	_ = os.Remove(dst)
	return os.WriteFile(dst, data, mode)
}

// setupMenuBarAgent installs the menu bar item as a per-user LaunchAgent.
//
// /Library/LaunchAgents rather than ~/Library: the agent is installed once,
// machine-wide, and the icon should appear for whoever logs in — not only for
// the account that happened to run the installer.
//
// launchd starts a LaunchAgent in each GUI session automatically, so nothing
// here has to find the logged-in user or bootstrap anything into their
// session.
func setupMenuBarAgent() error {
	// From inside this binary first, for the same reason the session helper is
	// embedded: the agent is installed by copying one file, and anything that
	// has to travel separately eventually does not. A copy beside the agent is
	// still accepted, for a build made without the embed step.
	src := filepath.Join(filepath.Dir(installedAgentPath()), "wxt-agent-menubar")
	if _, err := traybin.Extract(src); err != nil {
		if _, statErr := os.Stat(src); statErr != nil {
			return fmt.Errorf("this build carries no menu bar program and none is installed")
		}
	}

	// Run the bundle's copy where there is one, and delete the loose one.
	//
	// Same reason as the daemon: a binary launched from /usr/local/bin is its
	// own privacy client. The menu bar item asks macOS for nothing at all, but
	// it used to run the permission check — which spawns the helper, which
	// does ask — and the row that created was in the MENU BAR's name. Keeping
	// one copy, inside the bundle, removes the possibility entirely.
	if bundled := runtimeMenuBarPath(); bundled != src {
		removeLooseCopy(src)
		src = bundled
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<!-- Aqua only. Without this launchd would also start it in non-GUI
	     contexts, where there is no menu bar to draw in and the process would
	     sit there achieving nothing. -->
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
</dict>
</plist>
`, agent.LaunchAgentLabel, src)

	if err := os.WriteFile(macLaunchAgent, []byte(plist), 0644); err != nil { // #nosec G306 -- launchd requires a world-readable plist
		return fmt.Errorf("could not write %s: %w", macLaunchAgent, err)
	}

	// Started in the console user's session now, so the icon appears without
	// waiting for a log-out. A failure here is not fatal: launchd loads it at
	// the next login regardless.
	if uid, err := consoleUserID(); err == nil {
		target := fmt.Sprintf("gui/%d", uid)
		_ = exec.Command("/bin/launchctl", "bootout", target+"/"+agent.LaunchAgentLabel).Run()
		_ = exec.Command("/bin/launchctl", "bootstrap", target, macLaunchAgent).Run()
	}
	return nil
}

// installedAgentPath is where the agent binary lives once installed.
func installedAgentPath() string { return filepath.Join(macInstallDir, "wxt-agent") }
