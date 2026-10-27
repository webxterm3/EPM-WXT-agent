//go:build darwin

package pendinginstall

import (
	"os"
	"strings"
	"testing"
)

// The agent's own identifier is written down in three places that no build
// compares: this package, the permission registration, and the Makefile that
// signs the bundle.
//
// A rename would not fail anything. It would turn the self-exemption off —
// the mounted bundle would carry the new identifier, this would still be
// looking for the old one, and installing the agent would start demanding an
// administrator password again on machines where nobody has one. That is a
// silent regression discovered by a person who cannot upgrade their Mac.
func TestTheAgentsIdentifierIsTheSameEverywhere(t *testing.T) {
	for _, place := range []struct {
		file string
		want string
	}{
		{"cmd/agent/registerperms_darwin.go", `macAppBundleID = "` + ownBundleID + `"`},
		{"Makefile", "MACOS_BUNDLE_PREFIX ?= " + strings.TrimSuffix(ownBundleID, ".app")},
	} {
		b, err := os.ReadFile("../../" + place.file)
		if err != nil {
			t.Fatalf("could not read %s: %v", place.file, err)
		}
		if !strings.Contains(string(b), place.want) {
			t.Errorf("%s no longer says %q, so the mounted agent bundle will not "+
				"be recognised as ours and installing it will ask for a password",
				place.file, place.want)
		}
	}
}
