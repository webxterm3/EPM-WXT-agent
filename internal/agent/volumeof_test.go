package agent

import "testing"

// The menu bar sends the BUNDLE path, because that is what it shows. The
// decisions are keyed by MOUNT POINT, because that is what tells one open
// image from another and what disappears when one is ejected.
//
// Getting this wrong does not fail loudly: the lookup simply misses, the
// request is silently dropped as "not something I offered", and the person
// who clicked sees a confirmation for an approval nobody will ever receive.
func TestTheMountPointIsTakenFromABundlePath(t *testing.T) {
	for _, c := range []struct{ bundle, want string }{
		{"/Volumes/Visual Studio Code/Visual Studio Code.app", "/Volumes/Visual Studio Code"},
		{"/Volumes/Claude/Claude.app", "/Volumes/Claude"},
		// Already a mount point.
		{"/Volumes/Docker", "/Volumes/Docker"},
		// Deeper than one level — still the volume.
		{"/Volumes/Thing/sub/Thing.app", "/Volumes/Thing"},
	} {
		if got := volumeOf(c.bundle); got != c.want {
			t.Errorf("volumeOf(%q) = %q, want %q", c.bundle, got, c.want)
		}
	}
}

// Anything outside /Volumes is not a mounted image, and must not resolve to
// something that looks like one.
func TestAPathOutsideVolumesIsNotAMount(t *testing.T) {
	for _, p := range []string{
		"/Applications/Claude.app",
		"/Users/someone/Downloads/Claude.dmg",
		"",
		"/",
		"Volumes/NoLeadingSlash",
	} {
		if got := volumeOf(p); got != "" {
			t.Errorf("volumeOf(%q) = %q, want empty", p, got)
		}
	}
}
