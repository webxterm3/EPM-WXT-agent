//go:build darwin

package agentstatus

// platformPath keeps the status beside the agent's logs, which is already a
// world-readable directory the agent owns.
func platformPath() string { return "/var/log/vsay/status.json" }
