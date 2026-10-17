//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The product presents ONE code identity to macOS, and that fact is spelled
// out in four separate places: this package's constant, the Makefile's
// MACOS_APP_ID, the Info.plist embedded in the session helper, and the
// CFBundleIdentifier the DMG script writes into the application bundle.
//
// Nothing makes them agree. If one drifts, the build still succeeds, the agent
// still runs, and remote control still works on any machine where the grant is
// already in place — while every NEW install silently goes back to asking for
// a separate permission per binary, under rows with no name and no icon. That
// is the failure this whole arrangement exists to prevent, and it would
// reappear without a single error message.

func repoRoot(t *testing.T) string {
	t.Helper()
	// The test runs in cmd/agent.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Skipf("%s is not readable from here: %v", rel, err)
	}
	return string(data)
}

func TestTheHelperPlistCarriesTheAppIdentity(t *testing.T) {
	plist := readRepoFile(t, "build/macos/session-helper-info.plist")

	// <key>CFBundleIdentifier</key> followed by its <string>.
	re := regexp.MustCompile(`(?s)<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>`)
	m := re.FindStringSubmatch(plist)
	if m == nil {
		t.Fatal("the helper's Info.plist declares no CFBundleIdentifier — macOS would list it as a bare executable with a blank icon")
	}
	if got := strings.TrimSpace(m[1]); got != macAppBundleID {
		t.Errorf("the helper's Info.plist says %q, this package says %q.\n"+
			"They must match, or the helper asks for its own permission.", got, macAppBundleID)
	}
}

func TestTheMakefileSignsTheHelperWithTheAppIdentity(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	// MACOS_APP_ID is built from MACOS_BUNDLE_PREFIX, so the prefix is what
	// has to line up with the constant here.
	re := regexp.MustCompile(`MACOS_BUNDLE_PREFIX\s*\?=\s*(\S+)`)
	m := re.FindStringSubmatch(makefile)
	if m == nil {
		t.Fatal("the Makefile no longer defines MACOS_BUNDLE_PREFIX")
	}
	if want := m[1] + ".app"; want != macAppBundleID {
		t.Errorf("the Makefile would sign with %q, this package expects %q", want, macAppBundleID)
	}

	// And the helper must actually be signed with it rather than with an
	// identifier derived from its file name.
	if !strings.Contains(makefile, "sign_macos_identified,$(BIN_DIR)/darwin-arm64/wxt-agent-session,$(MACOS_APP_ID)") {
		t.Error("the arm64 helper is no longer signed with the application identifier")
	}
	if !strings.Contains(makefile, "check_helper_identity") {
		t.Error("the build no longer verifies the helper's identity — a drift here would be silent")
	}
}

func TestTheAppBundleUsesTheSameIdentity(t *testing.T) {
	script := readRepoFile(t, "scripts/build-dmg.sh")

	if !strings.Contains(script, `"${BUNDLE_PREFIX}.app"`) {
		t.Error("the DMG script no longer gives the application bundle the .app identifier")
	}
	// --deep would undo everything by rewriting every nested identifier.
	if strings.Contains(script, "codesign --force --deep") {
		t.Error("the DMG script signs with --deep again, which rewrites the helper's identifier and loses the grant")
	}
}

// The DMG must NOT re-sign the binaries the build already signed.
//
// It did, once, with different options — and that produced a copy of the
// session helper inside the application bundle that differed byte-for-byte
// from the copy embedded in the agent. The agent compares the two on every
// start and rewrites the installed helper when they differ, which broke the
// bundle's seal and threw away the privacy grant it had been given, over and
// over, with nothing in any log to say so.
func TestTheDMGDoesNotResignWhatTheBuildAlreadySigned(t *testing.T) {
	script := readRepoFile(t, "scripts/build-dmg.sh")

	for _, nested := range []string{
		`--identifier "$BUNDLE_PREFIX.app" \`,
		`--identifier "$BUNDLE_PREFIX.$(basename "$nested")"`,
	} {
		if strings.Contains(script, nested) {
			t.Errorf("the DMG script re-signs a nested binary (%s).\n"+
				"The build already signed it; signing again here makes the bundle copy "+
				"differ from the one embedded in the agent, and the agent then rewrites it "+
				"at runtime and breaks the bundle's seal.", nested)
		}
	}
}

// Every executable lives in Contents/MacOS and nowhere else.
//
// Each additional copy is an additional path, and macOS can key a privacy row
// to a path — a row no program can afterwards remove. Contents/Resources used
// to hold a second copy of all three binaries.
func TestExecutablesLiveOnlyInContentsMacOS(t *testing.T) {
	script := readRepoFile(t, "scripts/build-dmg.sh")

	for _, binary := range []string{"wxt-agent", "wxt-agent-session", "wxt-agent-menubar"} {
		stray := `"$APP/Contents/Resources/` + binary + `"`
		if strings.Contains(script, stray) {
			t.Errorf("the DMG script still stages %s in Contents/Resources; "+
				"a second copy is a second privacy client", binary)
		}
		if !strings.Contains(script, `"$APP/Contents/MacOS/`+binary+`"`) {
			t.Errorf("the DMG script no longer stages %s in Contents/MacOS", binary)
		}
	}
}

// The installer scripts must not put runnable copies back beside the bundle.
//
// Both of them delete the loose session helper on purpose. configure used to
// recreate it six lines later, which is how the product ended up arguing with
// itself about where its own binaries live.
func TestInstallersDoNotRecreateLooseCopies(t *testing.T) {
	appScript := readRepoFile(t, "scripts/macos-app/wxt-agent-app.sh")

	if !strings.Contains(appScript, `rm -f '$INSTALL_DIR/wxt-agent-session' '$INSTALL_DIR/wxt-agent-menubar'`) {
		t.Error("the installer no longer removes the loose helper and menu bar copies")
	}
	if strings.Contains(appScript, `cp '$RES/wxt-agent-menubar'`) {
		t.Error("the installer copies the menu bar item out of the bundle again — it should run from inside it")
	}

	configure := readRepoFile(t, "cmd/agent/configure_darwin.go")
	if !strings.Contains(configure, "remotecontrol.BundleHelperPath() != \"\"") {
		t.Error("configure no longer skips the loose helper copy when the bundle is present")
	}
	if !strings.Contains(configure, "runtimeAgentPath()") {
		t.Error("the LaunchDaemon no longer prefers the bundle's copy of the agent — " +
			"its helper launches would be attributed to a second, unbundled identity")
	}
}

// tccutil resolves what it is given through LaunchServices, so only an
// identifier belonging to a real registered bundle can ever be reset. This is
// the property that makes the uninstaller's purge — and configure's
// self-repair — do anything at all.
func TestTheIdentityIsSomethingTccutilCanReset(t *testing.T) {
	if _, err := exec.LookPath("tccutil"); err != nil {
		t.Skip("tccutil is not available")
	}
	if !strings.HasSuffix(macAppBundleID, ".app") {
		t.Errorf("%q does not look like the application bundle's identifier; "+
			"tccutil rejects anything that is not a registered bundle id", macAppBundleID)
	}
	for _, id := range tccIdentities {
		if id != macAppBundleID {
			t.Errorf("the uninstaller tries to reset %q, which belongs to no bundle — "+
				"tccutil answers \"No such bundle identifier\" and clears nothing", id)
		}
	}
}
