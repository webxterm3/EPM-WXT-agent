//go:build !darwin

package main

import "github.com/spf13/cobra"

// repair-permissions is macOS-only: no other platform gates remote control
// behind a privacy database. The command is absent rather than present and
// inert, so `wxt-agent help` on Windows does not advertise something that
// cannot do anything.
func newRepairPermissionsCommand() *cobra.Command { return nil }
