//go:build !darwin

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newCheckPermissionsCommand exists on every platform so the command is never
// simply missing — one that vanishes reads as a broken build.
func newCheckPermissionsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check-permissions",
		Short: "Check remote control's operating-system permissions (macOS only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Only macOS gates screen capture and input behind a permission the user must grant.")
			fmt.Println("On this platform there is nothing to check.")
			return nil
		},
	}
}
