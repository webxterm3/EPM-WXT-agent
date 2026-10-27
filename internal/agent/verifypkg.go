package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
)

// Verifying a downloaded package before running it.
//
// The agent fetches its own replacement over HTTP from a URL the server hands
// it, and until this existed it ran whatever came back. A package executes as
// root or SYSTEM, so "whatever came back" WAS the trust decision — a proxy, a
// redirect, or anything that could answer for that host chose what the fleet
// installed.
//
// The hashes are published beside the packages by `make deploy-binaries`, at
// the moment they are copied, so they cannot describe a different build to the
// one being served.
//
// Every failure here is CLOSED. No sums file, a package not listed in it, a
// hash that does not match — all refuse the update. A failed update leaves a
// working agent; an unverified one may leave something else entirely.

// sumsFileName is published next to the packages.
const sumsFileName = "SHA256SUMS"

// sumsURLFor returns where to find the hashes for a package URL.
//
// Derived from the package's own URL rather than configured separately, so
// the two cannot point at different servers — which would let one host supply
// the bytes and another vouch for them.
func sumsURLFor(pkgURL string) (string, error) {
	u, err := url.Parse(pkgURL)
	if err != nil {
		return "", err
	}
	if u.Path == "" {
		return "", fmt.Errorf("package URL has no path: %s", pkgURL)
	}
	u.Path = path.Join(path.Dir(u.Path), sumsFileName)
	// A cache-busting query belongs to the package, not to this.
	u.RawQuery = ""
	return u.String(), nil
}

// packageNameFromURL is the filename the sums file will list it under.
func packageNameFromURL(pkgURL string) string {
	if u, err := url.Parse(pkgURL); err == nil && u.Path != "" {
		return path.Base(u.Path)
	}
	return path.Base(pkgURL)
}

// parseSums reads `shasum -a 256` output into filename → hash.
//
// The format is "<64 hex>  <name>", two spaces. Lines that do not look like
// that are skipped rather than failing the file: a sums file that grows a
// comment or a blank line must not stop every agent in the fleet updating.
func parseSums(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != 64 {
			continue
		}
		if _, err := hex.DecodeString(sum); err != nil {
			continue
		}
		// The name may carry a "*" binary marker, and only the base name is
		// meaningful — a sums file listing "./wxt-agent-arm64.dmg" describes
		// the same package.
		name := path.Base(strings.TrimPrefix(fields[len(fields)-1], "*"))
		out[name] = sum
	}
	return out
}

// fileSHA256 hashes a file on disk.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the agent's own temp download
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyPackage checks a downloaded file against the published hashes.
//
// Returns an error describing what was wrong, in words that distinguish the
// three failures: nothing published, this package not published, and the bytes
// not matching. They mean different things — the first two are a deployment
// that is out of step, the third is the one to be alarmed about.
func verifyPackage(filePath, pkgURL string, sums map[string]string) error {
	name := packageNameFromURL(pkgURL)

	if len(sums) == 0 {
		return fmt.Errorf("no %s was published beside the package, so there is nothing "+
			"to check %s against", sumsFileName, name)
	}

	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s is not listed in %s, so its contents cannot be vouched for",
			name, sumsFileName)
	}

	got, err := fileSHA256(filePath)
	if err != nil {
		return fmt.Errorf("hashing the downloaded package: %w", err)
	}
	if got != want {
		return fmt.Errorf("the downloaded %s does not match the published hash "+
			"(expected %s, got %s) — it was altered in transit or the server is "+
			"serving a different build to the one it published", name, want[:16], got[:16])
	}
	return nil
}

// verifyDownloadedPackage fetches the published hashes and checks the file.
//
// The sums are fetched over the same TLS-verified transport the package came
// down, from the same host — so a proxy that can tamper with one can tamper
// with both, and the protection this gives is against a tampered PACKAGE, not
// a wholly compromised server. Said plainly because it is easy to believe a
// hash file proves more than it does; what actually raises that bar is
// signing, which needs a key the agent carries and is a separate change.
func (a *Agent) verifyDownloadedPackage(filePath, pkgURL string) error {
	sumsURL, err := sumsURLFor(pkgURL)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "wxt-agent-sums-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer a.removeQuiet(tmpPath)

	if err := a.downloadUpdate(sumsURL, tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fetching %s: %w", sumsFileName, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// #nosec G304 -- the agent's own temp file, written immediately above
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}
	return verifyPackage(filePath, pkgURL, parseSums(data))
}
