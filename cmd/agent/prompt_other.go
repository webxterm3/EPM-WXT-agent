//go:build !darwin

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newPromptCommand exists on every platform so the command is never simply
// missing; only the macOS application uses it.
func newPromptCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "prompt-enrolment",
		Short:  "Ask for the enrolment command in a dialog (macOS only)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("this command is only used by the macOS application")
		},
	}
}
