//go:build !darwin

package pendinginstall

// Dragging into /Applications is a macOS idea. Nothing to grant elsewhere.

func GrantDragInstall(string) error    { return nil }
func RevokeDragInstall(string)         {}
func ExpireDragGrants()                {}
func RevokeAllDragGrants()             {}
func InstalledBundleFor(string) string { return "" }

// RevokeStaleDragGrants has nothing to revoke: no grant is ever made here.
func RevokeStaleDragGrants() []string { return nil }

func GrantBundleRemoval(string, string) error { return nil }
func RevokeBundleRemoval(string, string)      {}
func ExpireBundleGrants()                     {}
func RevokeAllBundleGrants()                  {}
func RevokeStaleBundleGrants() []string       { return nil }
func InstalledApps() []string                 { return nil }

func RevokeBundleGrantsExcept(string, map[string]bool) {}
