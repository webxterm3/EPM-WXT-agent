package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// runUninstall removes the agent from this machine.
//
// One command rather than a script per platform, because it is also what
// Windows runs from Control Panel and what the macOS uninstaller bundle calls:
// three callers, one description of what "installed" means. A platform that
// grows a new artefact gets it removed everywhere at once.
func runUninstall(cmd *cobra.Command, args []string) error {
	yes, _ := cmd.Flags().GetBool("yes")
	keepConfig, _ := cmd.Flags().GetBool("keep-config")

	fmt.Println("This will remove the EPM agent from this machine:")
	for _, line := range uninstallPlan(keepConfig) {
		fmt.Println("  •", line)
	}
	fmt.Println()
	fmt.Println("No user account is changed — this agent never created one.")
	fmt.Println("The machine stays listed in the portal until an administrator removes it there.")
	fmt.Println()

	if !yes {
		fmt.Print("Continue? [y/N]: ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			fmt.Println("Cancelled. Nothing was changed.")
			return nil
		}
	}

	// Every step reports its own outcome and none of them stops the rest. An
	// uninstaller has to finish on a half-installed machine — which is exactly
	// the state somebody reaches for it in — and stopping at the first missing
	// file would leave everything after it behind.
	problems := uninstallAgent(keepConfig)

	fmt.Println()
	if len(problems) == 0 {
		fmt.Println("✓ EPM agent removed.")
	} else {
		fmt.Println("EPM agent removed, with some steps left undone:")
		for _, p := range problems {
			fmt.Println("  ✗", p)
		}
		fmt.Println()
		fmt.Println("Re-running this command with administrator rights usually clears these.")
	}
	printPostUninstallNotes()
	return nil
}

func newUninstallCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the agent, its service and its configuration from this machine",
		RunE:  runUninstall,
	}
	// --yes exists for Control Panel and the macOS uninstaller bundle, which
	// have already asked the person and have no console to ask again on.
	c.Flags().Bool("yes", false, "Do not ask for confirmation")
	c.Flags().Bool("keep-config", false, "Leave the configuration and certificates in place (for a reinstall)")
	return c
}
