package appinventory

import "context"

// MultiCollector runs several collectors and merges what they find.
//
// A machine's software does not come from one place. On macOS there are
// application bundles and whatever Homebrew has installed; on Windows the
// uninstall registry and whatever Chocolatey has. A fleet catalogue that shows
// only the first of each pair is not wrong so much as blind in exactly the
// direction that matters — package managers are how software arrives on a
// developer's machine without going anywhere near an installer, which is the
// case least-privilege work exists to see.
type MultiCollector struct {
	Label      string
	Collectors []Collector
}

func (m *MultiCollector) Name() string {
	if m.Label != "" {
		return m.Label
	}
	return "multi"
}

// Collect runs each collector in turn.
//
// One collector failing costs that collector's results and not the scan: a
// machine without Homebrew is the normal case, not an error, and a registry
// hive that cannot be read must not take the application bundles down with it.
// The first error is returned alongside whatever was found, so the backend
// still learns the scan was partial and declines its removal sweep.
func (m *MultiCollector) Collect(ctx context.Context) ([]Application, error) {
	var apps []Application
	var firstErr error

	for _, c := range m.Collectors {
		if c == nil {
			continue
		}
		if ctx.Err() != nil {
			return finalise(apps), ctx.Err()
		}
		found, err := c.Collect(ctx)
		apps = append(apps, found...)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return finalise(apps), firstErr
}
