package logship

// SourceOptions selects what a machine collects.
//
// It is kept separate from Config because the two answer different questions:
// Config is about how much may be shipped, this is about what is worth
// shipping in the first place. Narrowing here is always cheaper than
// throttling there.
type SourceOptions struct {
	// SystemLogs turns on the platform's own log — Windows Event Log or the
	// macOS unified log.
	SystemLogs bool

	// Websites turns on domain-level browsing activity, derived from DNS.
	Websites bool

	// WindowsChannels overrides DefaultWindowsChannels. Ignored elsewhere.
	WindowsChannels []string

	// IncludeInfoDebug collects info- and debug-level records too. It is off by
	// default: those are the great majority of the macOS unified log and are
	// rarely what an investigation needs, so turning this on can change a
	// machine's daily volume by an order of magnitude.
	IncludeInfoDebug bool

	// KeepRaw stores each record's original structured form. Errors and
	// criticals keep theirs regardless of this, so it mainly adds detail to
	// records nobody reads — at roughly double the size.
	KeepRaw bool
}

// DefaultSourceOptions collects the platform log and website activity, at
// default verbosity.
func DefaultSourceOptions() SourceOptions {
	return SourceOptions{SystemLogs: true, Websites: true}
}

// Enabled reports whether anything at all is being collected.
func (o SourceOptions) Enabled() bool { return o.SystemLogs || o.Websites }
