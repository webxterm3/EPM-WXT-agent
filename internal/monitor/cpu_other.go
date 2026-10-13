//go:build !darwin

package monitor

import "fmt"

// cpuPercentFallback exists only on darwin; see cpu_darwin.go. Everywhere else
// gopsutil reads CPU times from the kernel without cgo, so a failure here is a
// real failure and must not be papered over with a second guess.
func cpuPercentFallback() (float32, error) {
	return 0, fmt.Errorf("no fallback on this platform")
}
