//go:build darwin

package pendinginstall

import (
	"strings"
	"testing"

	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// stubOwnIdentity makes the agent believe it was signed by one certificate,
// and makes codesign answer for a known set of bundles.
func stubOwnIdentity(t *testing.T, requirement string, satisfied map[string]bool) *[]string {
	t.Helper()
	origReq, origCheck := ownRequirement, satisfiesRequirement
	var asked []string

	ownRequirement = func() string { return requirement }
	satisfiesRequirement = func(bundle, req string) bool {
		asked = append(asked, bundle+" ?? "+req)
		return req == requirement && satisfied[bundle]
	}
	t.Cleanup(func() { ownRequirement, satisfiesRequirement = origReq, origCheck })
	return &asked
}

const ourRequirement = `identifier "io.coredge.epm.app" and certificate root = H"0b34b6a1"`

func ourInstaller(path string) MountedApp {
	return MountedApp{
		Volume:     "/Volumes/wxt-agent 1.0.0",
		BundlePath: path,
		Name:       "wxt-agent",
		BundleID:   ownBundleID,
		Publisher:  "EPM Agent Code Signing",
	}
}

// The machines that most need this are the ones with no policy at all: a
// fresh enrolment, or one whose policy was deleted. Expressing the exemption
// as a policy row would fail on exactly those — and the failure seals itself
// shut, because the way out of a refused agent install is an approval
// request, and it is the agent that raises them.
func TestTheAgentsOwnInstallerNeedsNoPolicyToBeAllowed(t *testing.T) {
	app := ourInstaller("/Volumes/wxt-agent 1.0.0/wxt-agent.app")
	stubOwnIdentity(t, ourRequirement, map[string]bool{app.BundlePath: true})

	d := DecideMounted(app, nil) // no policy has ever reached this machine
	if d.Outcome != OutcomeInstallable {
		t.Fatalf("the agent's own installer answers %q (%s)", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "without a password") {
		t.Errorf("reason %q does not say it installs without a password", d.Reason)
	}
}

// And a policy that blocks everything must not be able to lock the agent out
// of being upgraded — otherwise one broad rule bricks the fleet's management.
func TestNoPolicyCanBlockTheAgentsOwnUpgrade(t *testing.T) {
	app := ourInstaller("/Volumes/wxt-agent 1.0.0/wxt-agent.app")
	stubOwnIdentity(t, ourRequirement, map[string]bool{app.BundlePath: true})

	if d := DecideMounted(app, blockByName("wxt-agent")); d.Outcome != OutcomeInstallable {
		t.Fatalf("a block rule stopped the agent upgrading itself: %q (%s)", d.Outcome, d.Reason)
	}
}

// THE security property. The exemption grants a drag into /Applications with
// no password, so anything that can claim it is an unprivileged write
// primitive. A self-signed certificate whose common name reads "EPM Agent
// Code Signing" takes one command to mint, and a folder can be called
// anything — so neither the name nor the publisher string may be what is
// trusted.
func TestABundleSignedByAnotherCertificateIsNotTheAgent(t *testing.T) {
	impostor := MountedApp{
		Volume:     "/Volumes/wxt-agent 9.9.9",
		BundlePath: "/Volumes/wxt-agent 9.9.9/wxt-agent.app",
		Name:       "wxt-agent",
		BundleID:   ownBundleID,              // claims our identifier
		Publisher:  "EPM Agent Code Signing", // and our publisher string
	}
	// codesign says no: a different certificate root.
	stubOwnIdentity(t, ourRequirement, map[string]bool{})

	d := DecideMounted(impostor, nil)
	if d.Outcome == OutcomeInstallable {
		t.Fatalf("a bundle signed by somebody else was treated as the agent "+
			"and handed a password-free write into /Applications: %s", d.Reason)
	}
}

// A bundle that simply is not us must not even cost a codesign call.
func TestOtherSoftwareIsNotCheckedAgainstOurSignature(t *testing.T) {
	asked := stubOwnIdentity(t, ourRequirement, map[string]bool{})

	zoom := MountedApp{
		Volume:     "/Volumes/Zoom",
		BundlePath: "/Volumes/Zoom/zoom.us.app",
		Name:       "zoom.us",
		BundleID:   "us.zoom.xos",
		Publisher:  "Developer ID Application: Zoom Video Communications, Inc.",
	}
	if IsOwnPackage(zoom) {
		t.Fatal("Zoom was identified as the management agent")
	}
	if len(*asked) != 0 {
		t.Errorf("shelled out to codesign for software that is plainly not ours: %v", *asked)
	}
}

// An ad-hoc signature pins no certificate, so anybody can produce one that
// satisfies the same requirement. Refusing here costs an upgrade a password;
// trusting here costs root.
func TestAnAgentThatCannotProveItsOwnIdentityExemptsNothing(t *testing.T) {
	app := ourInstaller("/Volumes/wxt-agent 1.0.0/wxt-agent.app")
	stubOwnIdentity(t, "", map[string]bool{app.BundlePath: true})

	if IsOwnPackage(app) {
		t.Fatal("with no requirement of its own to compare against, the agent " +
			"exempted a bundle anyway")
	}
}

// The exemption must not leak to other software through the same code path.
func TestTheExemptionDoesNotChangeAnybodyElsesAnswer(t *testing.T) {
	stubOwnIdentity(t, ourRequirement, map[string]bool{})

	const pub = "Developer ID Application: Zoom Video Communications, Inc."
	zoom := MountedApp{Name: "zoom.us", BundleID: "us.zoom.xos", Publisher: pub}

	if d := DecideMounted(zoom, blockByName("zoom.us")); d.Outcome != OutcomeBlocked {
		t.Errorf("blocked software now answers %q", d.Outcome)
	}
	if d := DecideMounted(zoom, allowByName("zoom.us")); d.Outcome != OutcomeInstallable {
		t.Errorf("allowed software now answers %q", d.Outcome)
	}
	var none *apppolicy.Effective
	if d := DecideMounted(zoom, none); d.Outcome != OutcomeNoPolicy {
		t.Errorf("software on an unpolicied machine now answers %q", d.Outcome)
	}
}

// The agent's own installer is allowed but NOT offered.
//
// It is allowed so that upgrading the agent never needs a password. It is
// not offered because the agent is already running and updates itself: a
// row and a dialog asking whether to install it are an offer to do something
// nobody has to decide, and they came back every few seconds for as long as
// somebody left the disk image mounted.
func TestTheAgentsOwnInstallerIsNotOfferedToAnybody(t *testing.T) {
	app := ourInstaller("/Volumes/wxt-agent 1.0.0/wxt-agent.app")
	stubOwnIdentity(t, ourRequirement, map[string]bool{app.BundlePath: true})

	d := DecideMounted(app, nil)
	if !d.Own {
		t.Fatal("the agent's own installer is not recognised as its own, so it " +
			"will be offered for installing every time the image is mounted")
	}
	if d.Outcome != OutcomeInstallable {
		t.Errorf("outcome %q — the agent must still be allowed to upgrade", d.Outcome)
	}
}

// And nobody else's software is ever marked that way.
func TestOtherSoftwareIsNeverMarkedAsOurs(t *testing.T) {
	stubOwnIdentity(t, ourRequirement, map[string]bool{})

	zoom := MountedApp{Name: "zoom.us", BundleID: "us.zoom.xos", Publisher: "Developer ID Application: Zoom"}
	if DecideMounted(zoom, allowByName("zoom.us")).Own {
		t.Error("Zoom was marked as the agent's own package and would be hidden")
	}
}
