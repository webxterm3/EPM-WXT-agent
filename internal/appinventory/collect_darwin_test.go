//go:build darwin

package appinventory

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These run against the real machine. They assert shape and sanity rather than
// specific applications, because what is installed differs per machine — but
// a collector that returns nothing, or returns obvious junk, is caught.

func TestCollectFindsRealApplications(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Signatures are the slow part and are covered separately.
	apps, err := (&DarwinCollector{SkipSignatures: true}).Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Any Mac has at least the system applications.
	if len(apps) < 5 {
		t.Fatalf("found only %d applications; the collector is not reading the filesystem", len(apps))
	}

	ids := make(map[string]bool, len(apps))
	for _, app := range apps {
		if app.Name == "" {
			t.Errorf("application with no name: %+v", app)
		}
		if app.ID == "" {
			t.Errorf("application with no id: %+v", app)
		}
		if ids[app.ID] {
			t.Errorf("duplicate id %q — the same app would be counted twice", app.ID)
		}
		ids[app.ID] = true

		if !strings.HasSuffix(app.InstallPath, ".app") {
			t.Errorf("%q has install path %q, which is not a bundle", app.Name, app.InstallPath)
		}
		// Helper apps and XPC services live inside bundles. Finding one means
		// the walk descended into an application, which multiplies the
		// inventory with things nobody installed.
		if strings.Contains(app.InstallPath, ".app/Contents/") {
			t.Errorf("%q is inside another bundle: %s", app.Name, app.InstallPath)
		}
	}

	var system int
	for _, app := range apps {
		if app.Source == SourceSystemBundle {
			system++
		}
	}
	if system == 0 {
		t.Error("no system applications found — /System/Applications was not searched")
	}

	t.Logf("collected %d applications (%d system)", len(apps), system)
	for i, app := range apps {
		if i >= 8 {
			break
		}
		t.Logf("  %-34s %-18s %s", app.Name, app.Version, app.ID)
	}
}

func TestCollectReadsSignatures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	apps, err := (&DarwinCollector{Roots: []string{"/System/Applications"}}).Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(apps) == 0 {
		t.Fatal("no applications found under /System/Applications")
	}

	// Apple's own applications are always signed, so if none of them produced
	// a publisher the codesign path is broken.
	var signed int
	for _, app := range apps {
		if app.Publisher != "" {
			signed++
		}
	}
	if signed == 0 {
		t.Fatal("no publisher read from any system application — the codesign call is not working")
	}
	t.Logf("%d of %d system applications carry a publisher", signed, len(apps))
}

func TestMissingRootIsNotAnError(t *testing.T) {
	// Most machines do not have every search root. That is the normal case,
	// not a failure, and must not stop the scan.
	apps, err := (&DarwinCollector{
		Roots:          []string{"/nonexistent/path/xyz", "/System/Applications"},
		SkipSignatures: true,
	}).Collect(context.Background())

	if err != nil {
		t.Fatalf("a missing search root failed the scan: %v", err)
	}
	if len(apps) == 0 {
		t.Error("the readable root was not scanned")
	}
}
