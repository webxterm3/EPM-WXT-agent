//go:build darwin

package pendinginstall

import (
	"path/filepath"
	"strings"
	"sync"
)

// What an installed application IS, remembered.
//
// Policy is written against four things — name, publisher, bundle id and
// path — and the removal pass was judging installed software on two of them,
// leaving the other two empty. The matcher fails any rule that constrains a
// field it is not given, so a rule allowing everything signed by Microsoft
// granted nobody permission to remove anything: the publisher it matched on
// was always "". Only rules written on the folder name worked, which is not
// what the person writing the policy was told they were doing.
//
// Read once per bundle rather than on every scan. The scan runs every three
// seconds and a Mac has on the order of a hundred applications; reading each
// one's Info.plist and verifying its signature every pass would be the agent
// making the machine slower in order to answer a question whose answer does
// not change until the application does.

// Identity is what an installed application reports about itself.
type Identity struct {
	Name      string
	BundleID  string
	Version   string
	Publisher string
}

var (
	installedMu    sync.Mutex
	installedCache = map[signerKey]Identity{}
)

// InstalledIdentity is what policy should be matched against for one
// installed application.
//
// Keyed on device and inode as well as path, like the signer cache: replacing
// an application in place gives a new inode, so an upgrade is re-read rather
// than answered from the old copy.
func InstalledIdentity(bundle string) Identity {
	// The folder name is what somebody sees in their Applications folder and
	// is the fallback for everything else.
	fallback := Identity{
		Name: strings.TrimSuffix(filepath.Base(bundle), ".app"),
	}

	key, ok := bundleFingerprint(bundle)
	if !ok {
		return fallback
	}

	installedMu.Lock()
	cached, hit := installedCache[key]
	installedMu.Unlock()
	if hit {
		return cached
	}

	id := fallback
	id.BundleID, id.Version, id.Name = bundleIdentity(bundle, fallback.Name)
	id.Publisher = verifiedBundleSigner(bundle)

	// Only a complete answer is remembered, for the same reason the signer
	// cache remembers only a successful verification: a read that failed
	// once must not become the permanent truth about an application.
	if id.BundleID != "" && id.Publisher != "" {
		installedMu.Lock()
		installedCache[key] = id
		installedMu.Unlock()
	}
	return id
}

// ForgetUninstalledIdentities drops entries for applications that are no
// longer there, so the cache does not grow for the life of the agent.
func ForgetUninstalledIdentities(live []string) {
	keep := make(map[signerKey]bool, len(live))
	for _, bundle := range live {
		if key, ok := bundleFingerprint(bundle); ok {
			keep[key] = true
		}
	}

	installedMu.Lock()
	defer installedMu.Unlock()
	for key := range installedCache {
		if !keep[key] {
			delete(installedCache, key)
		}
	}
}
