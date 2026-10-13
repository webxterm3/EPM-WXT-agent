//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"

	"github.com/Yesveer/wxt-agent/internal/brand"
)

// arpKey is where Windows looks for installed programs.
//
// HKLM, not HKCU: the agent is a machine-wide service installed by an
// administrator, and listing it per-user would hide it from the administrator
// who actually has to remove it.
const arpKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\EPMAgent`

// registerInAddRemovePrograms makes the agent visible in
// Control Panel → Programs and Features.
//
// Needed because the portal's enrolment command downloads the bare .exe and
// runs `configure`: no Windows installer runs, so nothing registers the
// product. The machine ended up with a service nobody could find, let alone
// remove, through any of the places an administrator would look.
//
// Best-effort by design. Failing to write a cosmetic registry key must not
// fail an enrolment that otherwise succeeded — the agent still works, it is
// just not listed.
func registerInAddRemovePrograms(installedExe, configDir, version string) {
	// A real Windows installer, if one was used, has already written this key
	// and knows how to remove its own shortcuts and uninstall.exe. Overwriting
	// its UninstallString would point Control Panel at the agent's uninstall
	// instead, which does not know about any of that and would leave it
	// behind. The entry already being correct is a reason to stop, not to
	// write over it.
	if existing, err := registry.OpenKey(registry.LOCAL_MACHINE, arpKey, registry.QUERY_VALUE); err == nil {
		s, _, readErr := existing.GetStringValue("UninstallString")
		existing.Close()
		if readErr == nil && s != "" {
			return
		}
	}

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, arpKey, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("Warning: could not register in Programs and Features: %v\n", err)
		return
	}
	defer k.Close()

	// UninstallString is what Control Panel runs when somebody presses
	// Uninstall. It points at the agent's own uninstall command, so there is
	// exactly one piece of code that knows how to remove this product.
	// The icon is written beside the configuration and pointed at from here.
	//
	// A Go executable carries no icon resource, so pointing DisplayIcon at the
	// .exe gives Programs and Features a blank page — which, in a list
	// somebody is reading to decide whether the product installed correctly,
	// looks exactly like a failed install. Embedding the file and writing it
	// out costs 23KB and nothing has to travel separately.
	icon := installedExe
	iconPath := filepath.Join(configDir, "wxt-agent.ico")
	if err := os.WriteFile(iconPath, brand.Icon, 0o644); err == nil { // #nosec G306 -- artwork, meant to be read
		icon = iconPath
	}

	values := map[string]string{
		"DisplayName":          "wxt-agent",
		"DisplayVersion":       version,
		"Publisher":            "Coredge",
		"InstallLocation":      configDir,
		"DisplayIcon":          icon,
		"UninstallString":      fmt.Sprintf(`"%s" uninstall --yes`, installedExe),
		"QuietUninstallString": fmt.Sprintf(`"%s" uninstall --yes`, installedExe),
	}
	for name, value := range values {
		if err := k.SetStringValue(name, value); err != nil {
			fmt.Printf("Warning: could not write %s: %v\n", name, err)
		}
	}

	// NoModify/NoRepair remove the buttons Control Panel would otherwise show
	// for operations this product does not have.
	_ = k.SetDWordValue("NoModify", 1)
	_ = k.SetDWordValue("NoRepair", 1)

	if fi, err := os.Stat(installedExe); err == nil {
		// EstimatedSize is in KiB and is what Control Panel displays. An entry
		// with no size reads as a broken install.
		_ = k.SetDWordValue("EstimatedSize", uint32(fi.Size()/1024)) // #nosec G115 -- a binary size in KiB
	}
}

// unregisterFromAddRemovePrograms removes the Programs and Features entry.
func unregisterFromAddRemovePrograms() {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, arpKey); err != nil {
		// Already gone is the normal case on a second run, and an uninstaller
		// has to finish on a half-installed machine.
		return
	}
}
