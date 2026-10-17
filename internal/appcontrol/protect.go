package appcontrol

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// isProtectedPath reports whether a path is off limits to enforcement
// whatever the policy says.
//
// These are the operating system's own programs. A rule that matches one of
// them is a mistake every time — nobody writes application control to stop
// users running the window server — and acting on it produces a machine that
// does not boot to a desktop. The policy engine is not trusted to have
// excluded them, because the engine evaluates what an operator typed.
func isProtectedPath(p string) bool {
	if p == "" {
		return true
	}
	n := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, prefix := range protectedPrefixes {
		if n == prefix || strings.HasPrefix(n, prefix+"/") {
			return true
		}
	}
	return false
}

var ownBinariesOnce sync.Once
var ownBinaries []string

// isOwnBinary reports whether a path is part of this agent.
//
// The agent blocking itself is the failure with no way out: it would stop its
// own process, or withhold the execute bit from its own binary, and then there
// is nothing left running that could be told to undo it. A policy broad enough
// to match the agent — "block everything not signed by us" on a fleet where
// this is not yet signed — is exactly the policy somebody will write.
func isOwnBinary(p string) bool {
	if p == "" {
		return false
	}
	ownBinariesOnce.Do(func() {
		if exe, err := os.Executable(); err == nil {
			if resolved, err := filepath.EvalSymlinks(exe); err == nil {
				exe = resolved
			}
			ownBinaries = append(ownBinaries, indexKey(exe))
			// The whole directory, which is what catches the session helper
			// and the status-area item sitting beside the agent.
			ownBinaries = append(ownBinaries, indexKey(filepath.Dir(exe)))
		}
		for _, extra := range ownInstallPaths {
			ownBinaries = append(ownBinaries, indexKey(extra))
		}
	})

	n := indexKey(p)
	for _, own := range ownBinaries {
		if own == "" {
			continue
		}
		if n == own || strings.HasPrefix(n, own+"/") {
			return true
		}
	}
	return strings.Contains(filepath.Base(n), "wxt-agent")
}
