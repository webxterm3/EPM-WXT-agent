package agent

import (
	"net/url"
	"path"
	"strings"
)

// updatePackageSuffix is the extension the downloaded package must be given.
//
// The update is written to a temp file, and the macOS extractor chooses how to
// open it from the file's EXTENSION — a disk image is mounted, a tarball is
// unpacked. os.CreateTemp("", "wxt-agent-update-*") produces
// "wxt-agent-update-2651304958", which has no extension, so neither branch
// matched and the extractor reported "this package carries no bundle".
//
// That was not reported as a failure. The caller treats "no bundle" as a
// legitimate answer — a tarball of a bare binary is a real kind of update —
// so it fell through to replacing the loose binary, which on macOS lives
// inside the signed application bundle and is refused. The download had
// already succeeded; the log said the update was refused for a reason that
// had nothing to do with the real cause.
//
// So the temp file is named after what was actually fetched.
func updatePackageSuffix(downloadURL string) string {
	name := downloadURL
	// A query string is not part of the filename. The portal cache-busts its
	// own download links with ?t=…, and "wxt-agent-arm64.dmg?t=1761" ends in
	// neither ".dmg" nor anything else useful.
	if u, err := url.Parse(downloadURL); err == nil && u.Path != "" {
		name = u.Path
	}
	name = strings.ToLower(path.Base(name))

	// Longest first: ".tar.gz" also ends in ".gz", and unpacking it as a bare
	// gzip stream would produce a tar file nobody then untars.
	for _, suffix := range []string{".tar.gz", ".tgz", ".dmg", ".exe", ".deb", ".zip"} {
		if strings.HasSuffix(name, suffix) {
			return suffix
		}
	}
	return ""
}

// updateTempPattern is the os.CreateTemp pattern for a downloaded package.
//
// The random part has to come BEFORE the extension, or the extension is not
// the end of the name and nothing matching on a suffix will see it.
func updateTempPattern(downloadURL string) string {
	return "wxt-agent-update-*" + updatePackageSuffix(downloadURL)
}
