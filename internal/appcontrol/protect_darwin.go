//go:build darwin

package appcontrol

// protectedPrefixes are the parts of macOS that enforcement never touches.
//
// /System and /usr are also protected by SIP, so an attempt would fail rather
// than do damage — but failing loudly every two minutes for every system
// binary is its own problem, and /Library holds launch daemons that are not
// SIP-protected and absolutely can break a machine.
var protectedPrefixes = []string{
	"/system",
	"/usr/bin",
	"/usr/sbin",
	"/usr/libexec",
	"/usr/lib",
	"/bin",
	"/sbin",
	"/library/apple",
	"/library/launchdaemons",
	"/library/launchagents",
	"/library/privilegedhelpertools",
	"/applications/utilities",
}

// ownInstallPaths are where this product's own files live on macOS.
var ownInstallPaths = []string{
	"/usr/local/bin/wxt-agent",
	"/opt/vsay",
	"/Library/Application Support/vsay",
	"/Applications/wxt-agent.app",
}
