//go:build !darwin

package input

// AccessibilityTrusted is a macOS question. Everywhere else input injection
// needs no grant, so reporting "not trusted" would be a false alarm.
func AccessibilityTrusted() bool { return true }

// RequestAccessibility is a macOS prompt; elsewhere there is nothing to ask
// for and nothing to register.
func RequestAccessibility() bool { return true }
