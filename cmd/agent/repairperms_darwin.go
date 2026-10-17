//go:build darwin

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newRepairPermissionsCommand clears this product's privacy grants so macOS
// asks again.
//
// It exists as a COMMAND, run by a person who has decided to run it, and not
// as something configure does on its own. An earlier version cleared the grant
// automatically whenever a permission check came back denied — which cannot
// distinguish "this row is stale" from "nobody has switched it on yet", and so
// destroyed the working grant on every enrolment. Resetting a permission is a
// destructive act and it now needs somebody to ask for it.
func newRepairPermissionsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "repair-permissions",
		Short: "Clear this product's Accessibility and Screen Recording grants so macOS asks again",
		Long: "Use this when a row in System Settings is switched ON but remote control is\n" +
			"still refused. That means the grant was recorded against an earlier build of\n" +
			"the binary and no longer applies to the one running now.\n\n" +
			"Only this product's own rows are touched. Nothing else on the machine is\n" +
			"affected.",
		RunE: func(cmd *cobra.Command, args []string) error {
			uid, err := consoleUserID()
			if err != nil {
				return fmt.Errorf("nobody is logged in at the screen: %w", err)
			}

			fmt.Printf("Clearing privacy grants for %s…\n", macAppBundleID)
			if cleared := clearStalePermissionRows(uid); cleared {
				fmt.Println("✓ Cleared. macOS will ask again the next time a session starts.")
			} else {
				fmt.Println("Nothing to clear — this product holds no grant macOS can see.")
				fmt.Println()
				fmt.Println("If a row is still listed in System Settings, it belongs to a path")
				fmt.Println("macOS keys separately and only you can remove it, with \"−\".")
			}

			helper := bundledHelperPath()
			if helper == "" {
				return nil
			}
			fmt.Println()
			fmt.Println("Asking again so the rows reappear…")
			if _, ok := askForPermissions(helper, uid); ok {
				fmt.Println("✓ Both grants apply.")
				return nil
			}
			fmt.Println("Switch on the \"wxt-agent\" row — the one with the product icon — in")
			fmt.Println("System Settings › Privacy & Security › Accessibility and Screen Recording.")
			return nil
		},
	}
}
