package appinventory

import (
	"path/filepath"
	"strings"
)

// This file holds the interpretation of macOS application bundles. Like
// windows_registry.go it carries no build tag, so the decisions — what counts
// as an application, which of several name fields to believe, who the
// publisher is — stay testable away from a Mac.

// Bundle sources. They are kept apart because an operator writing policy needs
// to know which applications ship with the OS: blocking those is how a machine
// becomes unusable, and it should never happen by accident in a broad rule.
const (
	SourceBundle       = "bundle"
	SourceSystemBundle = "system-bundle"
)

// bundleInfo is the subset of Info.plist that we use.
//
// The plist is read through `plutil -convert json`, because Info.plist is
// frequently in Apple's binary format which the standard library cannot
// decode, and shelling out to the system tool avoids taking on a plist
// dependency for this one job. That matches how the agent already reads
// `log show`, `ioreg` and `dscl`.
type bundleInfo struct {
	CFBundleIdentifier         string `json:"CFBundleIdentifier"`
	CFBundleName               string `json:"CFBundleName"`
	CFBundleDisplayName        string `json:"CFBundleDisplayName"`
	CFBundleShortVersionString string `json:"CFBundleShortVersionString"`
	CFBundleVersion            string `json:"CFBundleVersion"`
	CFBundlePackageType        string `json:"CFBundlePackageType"`
	CFBundleExecutable         string `json:"CFBundleExecutable"`
}

// nonApplicationPackageTypes are bundle types that are not launchable
// applications. A framework or plug-in inside an application directory is not
// something an operator installs, sees, or writes policy about.
var nonApplicationPackageTypes = map[string]bool{
	"FMWK": true, // framework
	"BNDL": true, // loadable bundle / plug-in
	"XPC!": true, // XPC service
}

// applicationFromBundle interprets one .app bundle.
//
// authority is the signing identity from codesign, or empty when the bundle is
// unsigned or codesign could not be run; it is best-effort because a scan must
// not fail over one unreadable signature.
func applicationFromBundle(path string, info bundleInfo, authority string) (Application, bool) {
	if nonApplicationPackageTypes[strings.TrimSpace(info.CFBundlePackageType)] {
		return Application{}, false
	}

	name := bundleDisplayName(path, info)
	if name == "" {
		return Application{}, false
	}

	scope, owner := scopeAndOwnerForPath(path)

	app := Application{
		Name:        name,
		Version:     firstNonEmpty(info.CFBundleShortVersionString, info.CFBundleVersion),
		Publisher:   authority,
		InstallPath: path,
		ExePath:     bundleExecutablePath(path, info),
		BundleID:    strings.TrimSpace(info.CFBundleIdentifier),
		Source:      sourceForPath(path),
		Scope:       scope,
		OSUser:      owner,
	}
	app.ID = bundleAppID(path, app.BundleID, scope, owner)
	return app, true
}

// bundleAppID builds the per-machine identity for a bundle.
//
// The bundle identifier is the stable part on macOS — it survives renames and
// version bumps, which the display name does not. Only when a bundle has none
// does the path have to stand in.
//
// The owner is folded in for applications inside a home directory, for the
// same reason as on Windows: two people can each keep a copy of the same app
// in their own ~/Applications, and those are two installs. Keying on the
// bundle id alone would silently collapse them into one.
func bundleAppID(path, bundleID, scope, owner string) string {
	identity := "path:" + path
	if bundleID != "" {
		identity = "bundle:" + strings.ToLower(bundleID)
	}
	if scope == ScopeUser {
		return "user:" + strings.ToLower(owner) + ":" + identity
	}
	return identity
}

// bundleExecutablePath returns the program inside the bundle.
//
// A path rule has to match what actually runs, and on macOS that is never the
// .app directory itself — it is the Mach-O binary under Contents/MacOS. An
// empty CFBundleExecutable means the bundle does not declare one, and guessing
// would produce a path that matches nothing.
func bundleExecutablePath(path string, info bundleInfo) string {
	exe := strings.TrimSpace(info.CFBundleExecutable)
	if exe == "" {
		return ""
	}
	return filepath.Join(path, "Contents", "MacOS", exe)
}

// scopeAndOwnerForPath reports whether an application belongs to one account.
//
// Software in a home directory is software somebody installed without admin
// rights, which is exactly what least-privilege work is about — so it has to
// be distinguishable from a machine-wide install, and attributable.
func scopeAndOwnerForPath(path string) (scope, owner string) {
	const usersPrefix = "/Users/"
	if !strings.HasPrefix(path, usersPrefix) {
		return ScopeMachine, ""
	}
	rest := strings.TrimPrefix(path, usersPrefix)
	name, _, found := strings.Cut(rest, "/")
	if !found || name == "" || name == "Shared" {
		return ScopeMachine, ""
	}
	return ScopeUser, name
}

// bundleDisplayName picks the name a person would recognise.
//
// The order matters: CFBundleDisplayName is what Finder shows, CFBundleName is
// often an abbreviated internal name, and the directory name is the last
// resort — but it is also the only one guaranteed to exist.
// bundleDisplayName is the name a person would call this application.
//
// The bundle's FOLDER NAME beats CFBundleName, and that ordering is the whole
// point of this function. CFBundleName is a short internal name — Apple's own
// guidance caps it at about 16 characters — so Visual Studio Code reports
// "Code", Microsoft Word reports "Microsoft Word" only by luck, and plenty of
// applications report something nobody has ever seen in the Finder.
//
// That mattered the moment policy arrived. Somebody looks at their
// Applications folder, writes a rule for "Visual Studio Code", and it silently
// matches nothing, because the inventory recorded "Code". The rule is correct,
// the engine is correct, and the product does nothing — which is the worst
// failure available to it.
//
// CFBundleDisplayName does not rescue it either, and that was the surprise:
// Visual Studio Code sets BOTH CFBundleName and CFBundleDisplayName to
// "Code". The Finder still shows "Visual Studio Code", because for a macOS
// application the Finder shows the bundle's file name — CFBundleDisplayName
// is mostly an iOS concern. So the folder name is the only field that agrees
// with what a person is looking at while they write the rule.
//
// The plist fields remain as fallbacks for a bundle whose folder name is
// missing or meaningless, which is the case this ordering gives up on.
func bundleDisplayName(path string, info bundleInfo) string {
	if n := collapseSpace(strings.TrimSuffix(filepath.Base(path), ".app")); n != "" {
		return n
	}
	if n := collapseSpace(info.CFBundleDisplayName); n != "" {
		return n
	}
	return collapseSpace(info.CFBundleName)
}

// sourceForPath marks OS-supplied applications.
func sourceForPath(path string) string {
	if strings.HasPrefix(path, "/System/") {
		return SourceSystemBundle
	}
	return SourceBundle
}

// parseCodesignAuthority pulls the signing identity out of codesign's output.
//
// codesign prints the certificate chain leaf-first, so the first Authority
// line is the signer — "Developer ID Application: Acme Inc (TEAMID)" for a
// third-party app, "Software Signing" for Apple's own. Later lines are the
// intermediate and root CAs, which are the same for everyone and identify
// nobody.
func parseCodesignAuthority(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		rest, found := strings.CutPrefix(line, "Authority=")
		if !found {
			continue
		}
		if authority := collapseSpace(rest); authority != "" {
			return authority
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if c := collapseSpace(v); c != "" {
			return c
		}
	}
	return ""
}
