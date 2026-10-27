//go:build !darwin

package pendinginstall

import (
	"path/filepath"
	"strings"
)

type Identity struct {
	Name      string
	BundleID  string
	Version   string
	Publisher string
}

// InstalledIdentity is macOS-only; application bundles are.
func InstalledIdentity(bundle string) Identity {
	return Identity{Name: strings.TrimSuffix(filepath.Base(bundle), ".app")}
}

// ForgetUninstalledIdentities has nothing to forget here.
func ForgetUninstalledIdentities([]string) {}
