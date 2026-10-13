//go:build darwin

package main

import (
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
