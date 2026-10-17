//go:build !darwin && !windows

package appcontrol

var protectedPrefixes = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/etc",
}

var ownInstallPaths = []string{"/usr/local/bin/wxt-agent", "/opt/vsay"}
