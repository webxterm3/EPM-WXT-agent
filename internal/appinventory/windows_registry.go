package appinventory

import (
	"strings"
	"time"
)

// This file holds the interpretation of Windows uninstall-registry values. It
// carries no build tag on purpose: the registry reads live in
// collect_windows.go, so the part with the actual judgement in it — what
// counts as an installed application and what is debris — stays testable from
// any machine.

// Registry views scanned. A 64-bit Windows keeps two separate uninstall trees,
// and a per-user tree alongside them; software installed "just for me" appears
// only in the last one and is invisible to a scan that reads only HKLM.
const (
	ViewMachine64 = `HKLM`
	ViewMachine32 = `HKLM\WOW6432Node`
	ViewUser      = `HKCU`
)

// RegistryEntry is the raw value set read from one uninstall subkey.
type RegistryEntry struct {
	// KeyName is the subkey itself — a product GUID or a vendor's own string.
	// It is the stable identity: display names change with version bumps,
	// subkeys generally do not.
	KeyName string
	View    string

	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallLocation string
	InstallDate     string
	UninstallString string

	// ReleaseType marks updates — "Security Update", "Update Rollup", "Hotfix".
	ReleaseType string

	// ParentKeyName is set when this entry patches another product.
	ParentKeyName string

	// SystemComponent is 1 for entries Windows itself hides from Add/Remove
	// Programs: redistributables, driver packages, installer plumbing.
	SystemComponent uint64

	// DisplayIcon usually points at the program's own executable, which is
	// the closest thing the uninstall registry has to "what actually runs".
	DisplayIcon string

	// Scope and OSUser describe which hive the entry came from.
	Scope  string
	OSUser string
}

// updateReleaseTypes are entries that are patches, not products.
//
// A fully patched Windows carries hundreds of these. Reporting them would bury
// the actual applications an operator is trying to write policy about, and
// they are not independently installable or blockable anyway.
var updateReleaseTypes = map[string]bool{
	"security update": true,
	"update rollup":   true,
	"hotfix":          true,
	"servicepack":     true,
	"service pack":    true,
	"update":          true,
}

// applicationFromRegistry interprets one uninstall entry, reporting false for
// anything that is not a user-visible installed application.
func applicationFromRegistry(e RegistryEntry) (Application, bool) {
	if strings.TrimSpace(e.DisplayName) == "" {
		// No display name means nothing to show and nothing to match a policy
		// against. These are overwhelmingly leftover or placeholder keys.
		return Application{}, false
	}
	if e.SystemComponent == 1 {
		return Application{}, false
	}
	if strings.TrimSpace(e.ParentKeyName) != "" {
		return Application{}, false
	}
	if updateReleaseTypes[strings.ToLower(strings.TrimSpace(e.ReleaseType))] {
		return Application{}, false
	}

	app := Application{
		ID:          registryAppID(e),
		Name:        e.DisplayName,
		Version:     e.DisplayVersion,
		Publisher:   e.Publisher,
		InstallPath: e.InstallLocation,
		ExePath:     exePathFromDisplayIcon(e.DisplayIcon),
		Source:      "registry",
		Scope:       e.Scope,
		OSUser:      e.OSUser,
		Arch:        archForView(e.View),
	}
	if t, ok := parseRegistryInstallDate(e.InstallDate); ok {
		app.InstalledAt = t
	}
	return app, true
}

// registryAppID builds the per-machine identity for an uninstall entry.
//
// The subkey is lowercased so the same product found in both the 32- and
// 64-bit views collapses to one record instead of being counted twice.
//
// The scope and owner are part of the identity, which is not an optimisation:
// two people on a shared machine can each install Chrome for themselves, and
// those are genuinely two installs. Keying on the subkey alone would make the
// second one overwrite the first, so the machine would report one Chrome and
// uninstalling it for one user would look like it vanished for both.
func registryAppID(e RegistryEntry) string {
	key := strings.ToLower(strings.TrimSpace(e.KeyName))
	if e.Scope == ScopeUser {
		return "registry:user:" + strings.ToLower(strings.TrimSpace(e.OSUser)) + ":" + key
	}
	return "registry:machine:" + key
}

// archForView infers the build from which registry tree the entry was in.
//
// This is an inference, not a fact the registry states: the WOW6432Node tree
// exists precisely to hold 32-bit entries on a 64-bit system.
func archForView(view string) string {
	switch view {
	case ViewMachine32:
		return "x86"
	case ViewMachine64:
		return "x64"
	default:
		return ""
	}
}

// parseRegistryInstallDate reads the InstallDate value.
//
// The documented format is YYYYMMDD, but installers write whatever they like,
// so several shapes are accepted and an unrecognised one is reported as absent
// rather than guessed at — a wrong install date is worse than none.
func parseRegistryInstallDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"20060102", "2006/01/02", "2006-01-02", "01/02/2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			// Windows itself writes 1601-01-01 (the FILETIME epoch) when it
			// means "unknown"; treating that as a real date would make the
			// whole fleet look like it was installed before Windows existed.
			if t.Year() < 1980 || t.After(time.Now().AddDate(1, 0, 0)) {
				return time.Time{}, false
			}
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// exePathFromDisplayIcon extracts the program path from a DisplayIcon value.
//
// The value is an icon reference, not a clean path: it is conventionally
// "C:\Path\app.exe,0" where the trailing number is the icon index, and it is
// frequently quoted. Taken literally it is useless for a path rule; stripped,
// it is the best guess the uninstall registry offers at which file actually
// runs. Entries pointing at a .ico or .dll are discarded — those are icons,
// not programs, and reporting one as the executable would make any path or
// hash rule written against it match nothing.
func exePathFromDisplayIcon(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.Trim(v, `"`)

	// Strip the trailing icon index, but only when it really is one — a comma
	// is legal in a Windows path.
	if i := strings.LastIndexByte(v, ','); i > 0 && isAllDigits(v[i+1:]) {
		v = v[:i]
	}
	v = strings.Trim(strings.TrimSpace(v), `"`)

	if !strings.EqualFold(filepathExt(v), ".exe") {
		return ""
	}
	return v
}

// filepathExt returns the lowercase extension, without importing path/filepath
// so this file stays free of platform path semantics.
func filepathExt(v string) string {
	if i := strings.LastIndexByte(v, '.'); i >= 0 {
		return strings.ToLower(v[i:])
	}
	return ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// applicationsFromRegistry interprets a batch of entries.
func applicationsFromRegistry(entries []RegistryEntry) []Application {
	out := make([]Application, 0, len(entries))
	for _, e := range entries {
		if app, ok := applicationFromRegistry(e); ok {
			out = append(out, app)
		}
	}
	return out
}
