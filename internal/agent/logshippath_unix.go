//go:build !windows

package agent

// logBookmarkFile records how far each log source has been shipped. It sits
// beside the agent's other state so a package upgrade, which replaces only the
// binary, cannot reset it and cause the whole retained history to re-ship.
var logBookmarkFile = "/etc/vsay/logship/bookmarks.json"
