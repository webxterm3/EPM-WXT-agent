package agent

import (
	"os"
	"strings"
	"testing"
)

// The downloaded package is opened according to its EXTENSION, and it used to
// be saved without one.
//
// os.CreateTemp("", "wxt-agent-update-*") produces "wxt-agent-update-2651304958".
// The extractor matched neither ".dmg" nor ".tar.gz", reported "no bundle
// here", and the caller treated that as a legitimate answer — so a perfectly
// good disk image fell through to the loose-binary path and was refused for
// being inside the application bundle. The download had already succeeded; the
// error named something unrelated to the cause.
func TestADownloadedPackageKeepsItsExtension(t *testing.T) {
	for _, c := range []struct{ url, want string }{
		{"http://host:8082/agent/download/wxt-agent-arm64.dmg", ".dmg"},
		{"http://host:8082/agent/download/wxt-agent-amd64.exe", ".exe"},
		{"http://host/agent/download/wxt-agent-macos-arm64.tar.gz", ".tar.gz"},
		{"http://host/x.tgz", ".tgz"},
	} {
		if got := updatePackageSuffix(c.url); got != c.want {
			t.Errorf("%s → %q, want %q", c.url, got, c.want)
		}
	}
}

// The portal cache-busts its download links. "wxt-agent-arm64.dmg?t=1761"
// ends in neither ".dmg" nor anything else a suffix match would find.
func TestAQueryStringIsNotPartOfTheName(t *testing.T) {
	if got := updatePackageSuffix("http://host/agent/download/wxt-agent-arm64.dmg?t=1761139200"); got != ".dmg" {
		t.Errorf("got %q — a cache-busted link would be saved with no extension "+
			"and the extractor could not read it", got)
	}
}

// ".tar.gz" also ends in ".gz". Matching the shorter one would have the
// extractor treat it as a bare gzip stream.
func TestTheLongestExtensionWins(t *testing.T) {
	if got := updatePackageSuffix("http://host/wxt-agent-macos-arm64.tar.gz"); got != ".tar.gz" {
		t.Errorf("got %q, want .tar.gz", got)
	}
}

// The random part has to come BEFORE the extension, or the extension is not
// at the end of the name and nothing matching on a suffix will see it.
func TestTheRealTempFileEndsInTheExtension(t *testing.T) {
	f, err := os.CreateTemp("", updateTempPattern("http://host/wxt-agent-arm64.dmg"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if !strings.HasSuffix(f.Name(), ".dmg") {
		t.Errorf("the package was saved as %q — the extractor dispatches on the "+
			"suffix and would not recognise it", f.Name())
	}
	if !strings.Contains(f.Name(), "wxt-agent-update-") {
		t.Errorf("%q is not identifiable as ours in a temp directory", f.Name())
	}
}

// An unknown or missing extension must not invent one. A package named
// something unexpected is better handled by the extractor reporting that it
// cannot read it than by being renamed into a format it is not.
func TestAnUnknownPackageGetsNoExtension(t *testing.T) {
	for _, u := range []string{"http://host/agent", "http://host/", "", "not a url at all"} {
		if got := updatePackageSuffix(u); got != "" {
			t.Errorf("%q produced the extension %q out of nothing", u, got)
		}
	}
}
