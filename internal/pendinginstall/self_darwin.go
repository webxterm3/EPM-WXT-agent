//go:build darwin

package pendinginstall

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

// The product's own installer must never need approval.
//
// Without this the agent judges its own disk image like any other software:
// nobody writes a policy rule about the management agent, so it resolves to
// "no rule covers this", the drag is refused, and installing or upgrading
// the agent demands an administrator password — on exactly the machines
// whose whole point is that the people using them do not have one. Worse,
// the way out of that state is an approval request, which is raised BY the
// agent, so a machine whose agent is too old to raise one cannot be fixed
// at all.

// ownBundleID is the one code identity this product presents to macOS.
//
// Must match macAppBundleID in cmd/agent/registerperms_darwin.go and
// MACOS_APP_ID in the Makefile; a drift test pins all three, because a
// rename would silently turn the exemption off rather than fail a build.
const ownBundleID = "io.coredge.epm.app"

// IsOwnPackage reports whether a mounted bundle really is this product's own
// installer.
//
// Identity, not name. Matching on "wxt-agent.app" or on the publisher string
// would be an unprivileged write primitive on /Applications: the exemption
// grants a drag that needs no password, so anybody who can name a folder —
// or mint a self-signed certificate whose common name reads "EPM Agent Code
// Signing", which takes one command — would have one.
//
// What is checked instead is that the mounted bundle satisfies a code
// requirement built from THIS RUNNING AGENT'S OWN signature: same bundle
// identifier, and the same certificate root. A build signed with a different
// certificate does not match, which is the point — the only thing exempt is
// another copy of the thing already trusted enough to be running as root.
func IsOwnPackage(app MountedApp) bool {
	// Cheap first, so the common case — somebody else's software — never
	// shells out at all.
	if app.BundleID != ownBundleID || app.BundlePath == "" {
		return false
	}
	req := ownRequirement()
	if req == "" {
		// No requirement could be derived, so nothing is exempt.
		//
		// This is the ad-hoc-signed case among others. An ad-hoc signature
		// pins no certificate, so anybody can produce one that satisfies the
		// same requirement, and an exemption resting on it would be no
		// exemption at all. Refusing here costs an upgrade a password;
		// trusting here costs root.
		return false
	}
	return satisfiesRequirement(app.BundlePath, req)
}

// ownRequirement is the code requirement describing this agent's own build.
//
// Derived once. The running executable cannot be re-signed underneath a
// running process in a way that matters here, and re-deriving it per scan
// would be two more codesign calls every few seconds.
var ownRequirement = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	root := certificateRootOf(exe)
	if root == "" {
		return ""
	}
	// Composed rather than reused whole. The designated requirement of the
	// binary and of the .app are not identical in general, and what matters
	// is only these two facts: it claims to be us, and it was signed by the
	// certificate that signed us.
	return `identifier "` + ownBundleID + `" and certificate root = H"` + root + `"`
})

// certRoot pulls the certificate root hash out of a designated requirement.
// An ad-hoc signature has no certificate clause, so this finds nothing.
var certRoot = regexp.MustCompile(`certificate root = H"([0-9a-fA-F]+)"`)

// certificateRootOf reads one binary's own designated requirement.
var certificateRootOf = func(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/codesign",
		"-d", "-r-", path).CombinedOutput()
	if err != nil {
		return ""
	}
	m := certRoot.FindSubmatch(out)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// satisfiesRequirement asks codesign whether a bundle meets a requirement.
//
// The EXIT CODE is the answer, and it is the only thing read. codesign
// prints nothing on success and "code failed to satisfy specified code
// requirement(s)" on failure, but parsing that message would make the check
// depend on wording Apple is free to change — and the failure direction of a
// wording change is that everything looks like ours.
var satisfiesRequirement = func(bundle, requirement string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err := exec.CommandContext(ctx, "/usr/bin/codesign",
		"--verify", "-R="+requirement, bundle).Run()
	return err == nil
}
