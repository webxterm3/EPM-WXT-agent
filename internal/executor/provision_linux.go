//go:build linux

package executor

import (
	"fmt"
	"os/exec"
	"os/user"

	"go.uber.org/zap"
)

// createUser creates a new Linux user
func (e *Executor) createUser() error {
	e.logger.Info("Creating user", zap.String("username", e.username))

	// Create user with home directory
	// useradd -m -s /bin/bash <username>
	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", e.username) // #nosec G204 -- argv-slice form, no shell involved
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd failed: %w, output: %s", err, string(output))
	}

	e.logger.Info("User created successfully", zap.String("username", e.username))

	// Add to sudo group if requested
	if e.allowSudo {
		if err := e.grantSudoAccess(); err != nil {
			e.logger.Warn("Failed to grant sudo access", zap.Error(err))
			// Don't fail, just log warning
		}
	}

	return nil
}

// grantSudoAccess adds the user to the sudo group
func (e *Executor) grantSudoAccess() error {
	e.logger.Info("Granting sudo access", zap.String("username", e.username))

	// Try different sudo group names depending on the distro
	sudoGroups := []string{"sudo", "wheel"}

	for _, group := range sudoGroups {
		// Check if group exists
		if _, err := user.LookupGroup(group); err != nil {
			continue
		}

		// usermod -aG <group> <username>
		cmd := exec.Command("usermod", "-aG", group, e.username) // #nosec G204 -- argv-slice form, no shell involved
		output, err := cmd.CombinedOutput()
		if err != nil {
			e.logger.Warn("Failed to add to group",
				zap.String("group", group),
				zap.Error(err),
				zap.String("output", string(output)),
			)
			continue
		}

		e.logger.Info("User added to sudo group",
			zap.String("username", e.username),
			zap.String("group", group),
		)
		return nil
	}

	return fmt.Errorf("no sudo group found (tried: %v)", sudoGroups)
}
