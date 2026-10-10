// Package appinventory collects the list of applications installed on the
// machine and reports it to the backend.
//
// This is the foundation of application control: a policy about software
// cannot be written, and certainly cannot be reasoned about before it is
// enforced, without first knowing what software is actually out there. The
// inventory is therefore deliberately a *complete* picture of installed
// software rather than a filtered one — the filtering decisions belong to the
// operator writing policy, not to the collector.
//
// Two properties shape the design:
//
// Identity. The same application has to be recognisable across scans, or every
// scan looks like the whole fleet reinstalled itself. Each record carries an
// ID derived from whatever the platform treats as stable — the registry
// subkey on Windows, the bundle identifier on macOS — not from the display
// name, which changes with every version bump of some products.
//
// Cost. This runs on somebody's laptop. Collection reads metadata only: no
// file hashing, no directory walking of application contents. Hashes are
// expensive enough (gigabytes of I/O) that they are fetched on demand for a
// specific application rather than computed for all of them on a schedule.
package appinventory

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Install scopes.
const (
	ScopeMachine = "machine"
	ScopeUser    = "user"
)

// Application is one installed program.
type Application struct {
	// ID is the stable per-machine identity used to match one scan against the
	// next. It is unique within a machine but says nothing across machines —
	// two laptops with the same app will have the same ID only by coincidence
	// of the platform's own naming.
	ID string `json:"id"`

	// Name is the display name an operator would recognise.
	Name string `json:"name"`

	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`

	// InstallPath is the directory the application lives in.
	InstallPath string `json:"install_path,omitempty"`

	// ExePath is the program that actually runs.
	//
	// It is kept apart from InstallPath because a path-based policy rule has to
	// match what gets executed, not the folder around it — and because a hash,
	// when one is requested, can only be taken of a file.
	ExePath string `json:"exe_path,omitempty"`

	// BundleID is the macOS CFBundleIdentifier. Empty on Windows.
	BundleID string `json:"bundle_id,omitempty"`

	// Scope distinguishes software installed for the whole machine from
	// software installed under one account.
	//
	// This matters more than it looks: a per-user install is exactly how
	// somebody without local admin rights installs software, so it is the
	// case least-privilege work exists to control. An inventory that cannot
	// tell the two apart is blind to the interesting half.
	Scope string `json:"scope,omitempty"`

	// OSUser is the account a user-scoped application belongs to.
	OSUser string `json:"os_user,omitempty"`

	// Source names where the record came from — "registry", "appx", "bundle".
	// Policy authors need it: a Store app and a classic installer are matched
	// and controlled by different means.
	Source string `json:"source"`

	// InstalledAt is the install date where the platform records one. Many
	// installers do not, so this is frequently zero and must not be relied on.
	InstalledAt time.Time `json:"installed_at,omitempty"`

	Arch string `json:"arch,omitempty"`
}

// Snapshot is a machine's complete installed-software list at one moment.
//
// It is a snapshot rather than a stream of changes because the platforms offer
// no reliable change notification for installs, and because a full list lets
// the backend reconcile idempotently — a repeat snapshot after an agent
// restart produces no duplicates.
type Snapshot struct {
	CollectedAt time.Time     `json:"collected_at"`
	OS          string        `json:"os"`
	Apps        []Application `json:"apps"`
}

// Collector gathers installed applications. Implementations are per-platform.
type Collector interface {
	// Name identifies the collector in logs.
	Name() string

	// Collect returns everything it can find. It returns a partial list with
	// no error where a single source is unreadable: one inaccessible registry
	// hive should cost that hive, not the entire scan.
	Collect(ctx context.Context) ([]Application, error)
}

// normalise cleans one record and reports whether it is worth keeping.
//
// Records with no name are dropped: they cannot be displayed, cannot be
// matched by a policy, and are overwhelmingly registry debris rather than
// software anybody installed.
func normalise(app Application) (Application, bool) {
	app.ID = strings.TrimSpace(app.ID)
	app.Name = collapseSpace(app.Name)
	app.Version = collapseSpace(app.Version)
	app.Publisher = collapseSpace(app.Publisher)
	app.InstallPath = strings.TrimSpace(app.InstallPath)
	app.ExePath = strings.TrimSpace(app.ExePath)
	app.BundleID = strings.TrimSpace(app.BundleID)

	if app.Name == "" {
		return Application{}, false
	}
	// An ID is what makes the record reconcilable. Falling back to the name is
	// worse than nothing only if the name is also empty, which is handled above.
	if app.ID == "" {
		app.ID = "name:" + strings.ToLower(app.Name)
	}
	return app, true
}

// collapseSpace trims and squeezes internal whitespace.
//
// Registry display names regularly carry trailing spaces and non-breaking
// spaces from installer templates. Left alone, the same product appears as two
// different applications across two machines and every fleet-wide count is
// quietly wrong.
func collapseSpace(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, " ", " ")), " ")
}

// finalise normalises, de-duplicates and orders a collected list.
//
// De-duplication matters because the same product legitimately appears in more
// than one place — a 32-bit and 64-bit registry view, or an app present in both
// /Applications and a user's own folder. Keeping both would double-count it in
// every report.
func finalise(apps []Application) []Application {
	seen := make(map[string]int, len(apps))
	out := make([]Application, 0, len(apps))

	for _, app := range apps {
		clean, ok := normalise(app)
		if !ok {
			continue
		}
		if i, dup := seen[clean.ID]; dup {
			// Prefer the record that carries more detail, so a sparse
			// duplicate cannot blank out a good one.
			if score(clean) > score(out[i]) {
				out[i] = clean
			}
			continue
		}
		seen[clean.ID] = len(out)
		out = append(out, clean)
	}

	// Stable order keeps the payload byte-identical between unchanged scans,
	// which makes "did anything change" cheap to answer.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// score counts the populated optional fields of a record.
func score(app Application) int {
	n := 0
	for _, v := range []string{app.Version, app.Publisher, app.InstallPath, app.ExePath, app.BundleID} {
		if v != "" {
			n++
		}
	}
	if !app.InstalledAt.IsZero() {
		n++
	}
	return n
}
