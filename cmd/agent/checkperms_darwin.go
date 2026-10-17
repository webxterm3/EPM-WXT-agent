//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

// newCheckPermissionsCommand reports whether remote control's macOS grants
// actually apply.
//
// It launches the session helper the way the agent does — launchctl asuser
// into the console user's GUI session — and asks it. That detail matters: a
// grant is evaluated for the process as it is actually started, so checking
// any other way answers a question nobody asked.
func newCheckPermissionsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check-permissions",
		Short: "Check whether remote control's Screen Recording and Accessibility grants apply",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Deferred so it is reported even when the remote-control checks
			// below bail out early. The two are separate permissions for
			// separate features, and a machine with no session helper still
			// has application control to answer for.
			defer reportAppManagement()

			helper, err := locateHelper()
			if err != nil {
				return err
			}
			fmt.Println("Session helper:", helper)

			uid, err := consoleUserID()
			if err != nil {
				return fmt.Errorf("%w\n\nRemote control needs somebody logged in at the screen", err)
			}
			fmt.Printf("Console user:   uid %d\n\n", uid)

			out, runErr := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(uid),
				helper, "--check-permissions").CombinedOutput()
			fmt.Print(string(out))

			if runErr != nil {
				// Exit code 1 means "denied", which the helper has already
				// printed in full. Anything else is a failure to even ask.
				if ee, ok := runErr.(*exec.ExitError); ok && ee.ExitCode() == 1 {
					os.Exit(1)
				}
				return fmt.Errorf("could not run the helper: %w", runErr)
			}
			return nil
		},
	}
}

// locateHelper finds the session helper, preferring the installed copy.
func locateHelper() (string, error) {
	// The SAME order the agent uses — the bundle first.
	//
	// This checked /usr/local/bin while the agent ran the copy inside
	// /Applications/wxt-agent.app, so the diagnostic reported "granted" for a
	// binary nobody was running while every session was refused. A tool built
	// to answer "does the grant apply?" has to ask about the process that
	// actually starts.
	candidates := []string{
		"/Applications/wxt-agent.app/Contents/MacOS/wxt-agent-session",
		"/usr/local/bin/wxt-agent-session",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "wxt-agent-session"))
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("the session helper is not installed; remote control is unavailable until it is")
}

// consoleUserID returns the uid of whoever owns the graphical console, the
// same way the agent finds it.
func consoleUserID() (int, error) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, fmt.Errorf("stat /dev/console: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type for /dev/console")
	}
	if st.Uid == 0 {
		return 0, fmt.Errorf("nobody is logged in at the console")
	}
	return int(st.Uid), nil
}

// reportAppManagement says whether the agent can prevent blocked applications
// from launching, or only close them once they have.
//
// It is checked by trying it rather than by reading a setting: there is no API
// that answers "do I have App Management", and the only honest test is the
// operation the enforcer actually performs. A bundle macOS has never seen
// something run from is not protected, so the probe builds one, runs it, and
// only then asks — which is the order that arms the protection in the first
// place.
//
// Reported rather than required. Without it, application control still works:
// a blocked program is closed within a few seconds of starting instead of
// never opening. That is a real difference and an operator should know which
// one they have, but it is not a reason to refuse to run.
func reportAppManagement() {
	fmt.Println()
	fmt.Println("Application control — preventing blocked apps from launching:")

	allowed, err := probeAppManagement()
	switch {
	case err != nil:
		fmt.Printf("  ? could not be checked: %v\n", err)
	case allowed:
		fmt.Println("  ✓ granted — blocked applications will not start at all")
	default:
		fmt.Println("  ✗ not granted — blocked applications will open and then be closed")
		fmt.Println()
		fmt.Println("    To prevent them opening at all, add wxt-agent in")
		fmt.Println("    System Settings › Privacy & Security › App Management.")
	}
}

// probeAppManagement performs the enforcer's own operation on a throwaway
// bundle and reports whether macOS allowed it.
func probeAppManagement() (bool, error) {
	dir, err := os.MkdirTemp("", "wxt-appmgmt")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	macOS := filepath.Join(dir, "Probe.app", "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		return false, err
	}
	binary := filepath.Join(macOS, "Probe")

	// A copy of a platform binary: macOS protects a bundle once something in
	// it has run, and a copy whose signature no longer matches is exactly the
	// shape of every third-party application on the machine.
	payload, err := os.ReadFile("/bin/sleep")
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(binary, payload, 0o755); err != nil { // #nosec G306 -- it must be executable to be a probe
		return false, err
	}

	run := exec.Command(binary, "30")
	if err := run.Start(); err == nil {
		// It is killed by the kernel for its broken signature almost at once;
		// what matters is that it was launched, which is what registers the
		// bundle.
		_ = run.Process.Kill()
		_, _ = run.Process.Wait()
	}

	if err := os.Chmod(binary, 0o644); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
