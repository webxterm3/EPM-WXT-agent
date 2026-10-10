//go:build windows

package appinventory

import (
	"context"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// uninstallSubkey is where Windows records installed software, under each of
// the machine and per-user roots.
const uninstallSubkey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// wow64UninstallSubkey is the 32-bit view's own copy.
const wow64UninstallSubkey = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

// WindowsCollector reads installed software from the uninstall registry.
type WindowsCollector struct {
	// IncludePerUser reads every loaded user hive as well as the machine ones.
	//
	// This is on by default and matters more than it looks: per-user installs
	// are precisely how someone without local admin rights installs software,
	// so an inventory that skips them is blind to exactly the software that
	// least-privilege work exists to control.
	SkipPerUser bool
}

// PlatformCollector returns the collector for this platform.
func PlatformCollector() Collector { return &WindowsCollector{} }

func (c *WindowsCollector) Name() string { return "windows-registry" }

func (c *WindowsCollector) Collect(ctx context.Context) ([]Application, error) {
	var entries []RegistryEntry

	// Machine-wide, both registry views. A 64-bit Windows keeps two separate
	// trees and most machines have software in both.
	entries = append(entries, readUninstallTree(registry.LOCAL_MACHINE, uninstallSubkey, ViewMachine64, ScopeMachine, "")...)
	entries = append(entries, readUninstallTree(registry.LOCAL_MACHINE, wow64UninstallSubkey, ViewMachine32, ScopeMachine, "")...)

	if !c.SkipPerUser {
		if ctx.Err() == nil {
			entries = append(entries, readAllUserHives()...)
		}
	}

	return finalise(applicationsFromRegistry(entries)), ctx.Err()
}

// readAllUserHives reads the uninstall tree of every loaded user profile.
//
// The agent runs as SYSTEM, so its own HKEY_CURRENT_USER is SYSTEM's profile —
// essentially empty, and not what anybody means by "installed for the user".
// Walking HKEY_USERS instead reaches the real accounts without needing to
// impersonate anyone. Only loaded hives are visible, which in practice means
// users who are logged in; a profile belonging to nobody currently signed in
// is simply not reported, rather than being silently wrong.
func readAllUserHives() []RegistryEntry {
	users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer users.Close()

	sids, err := users.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var entries []RegistryEntry
	for _, sid := range sids {
		if skipUserHive(sid) {
			continue
		}
		// The account name is resolved once per hive rather than per entry:
		// without it the record says "some user installed this", which is not
		// an answer anybody can act on.
		owner := accountNameForSID(sid)
		for _, sub := range []string{uninstallSubkey, wow64UninstallSubkey} {
			entries = append(entries, readUninstallTree(registry.USERS, sid+`\`+sub, ViewUser, ScopeUser, owner)...)
		}
	}
	return entries
}

// accountNameForSID turns a profile SID into DOMAIN\user, falling back to the
// SID itself. A SID is still a usable identifier; an empty owner is not.
func accountNameForSID(sid string) string {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return sid
	}
	account, domain, _, err := s.LookupAccount("")
	if err != nil || account == "" {
		return sid
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// skipUserHive filters HKEY_USERS entries that are not real user profiles.
//
// "_Classes" hives hold file associations, not installed software, and the
// built-in service accounts never have user-installed applications. Reading
// them is harmless but doubles the work for nothing.
func skipUserHive(sid string) bool {
	if strings.HasSuffix(sid, "_Classes") || sid == ".DEFAULT" {
		return true
	}
	// S-1-5-18/19/20 are LocalSystem, LocalService and NetworkService.
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	return false
}

// readUninstallTree enumerates one uninstall key.
//
// An unreadable root or subkey is skipped rather than failing the scan: a
// permission-denied on one profile should cost that profile, not the whole
// inventory.
func readUninstallTree(root registry.Key, path, view, scope, osUser string) []RegistryEntry {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	entries := make([]RegistryEntry, 0, len(names))
	for _, name := range names {
		sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		entries = append(entries, readUninstallEntry(sub, name, view, scope, osUser))
		sub.Close()
	}
	return entries
}

// readUninstallEntry pulls the values we interpret out of one subkey.
func readUninstallEntry(key registry.Key, name, view, scope, osUser string) RegistryEntry {
	e := RegistryEntry{KeyName: name, View: view, Scope: scope, OSUser: osUser}

	e.DisplayName = stringValue(key, "DisplayName")
	e.DisplayVersion = stringValue(key, "DisplayVersion")
	e.Publisher = stringValue(key, "Publisher")
	e.InstallLocation = stringValue(key, "InstallLocation")
	e.InstallDate = stringValue(key, "InstallDate")
	e.UninstallString = stringValue(key, "UninstallString")
	e.ReleaseType = stringValue(key, "ReleaseType")
	e.ParentKeyName = stringValue(key, "ParentKeyName")
	e.DisplayIcon = stringValue(key, "DisplayIcon")
	e.SystemComponent = integerValue(key, "SystemComponent")

	return e
}

// stringValue reads a string value, tolerating the wrong type.
//
// Installers write REG_EXPAND_SZ where REG_SZ is documented, and occasionally
// a number where a string belongs. A missing or unreadable value is simply
// absent — never a reason to drop the whole entry.
func stringValue(key registry.Key, name string) string {
	if s, _, err := key.GetStringValue(name); err == nil {
		return s
	}
	if s, _, err := key.GetStringsValue(name); err == nil && len(s) > 0 {
		return s[0]
	}
	return ""
}

func integerValue(key registry.Key, name string) uint64 {
	if n, _, err := key.GetIntegerValue(name); err == nil {
		return n
	}
	return 0
}
