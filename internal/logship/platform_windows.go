//go:build windows

package logship

import "go.uber.org/zap"

// PlatformSources builds the collectors available on Windows.
func PlatformSources(opts SourceOptions, logger *zap.Logger) []Source {
	var out []Source

	if opts.SystemLogs {
		src := NewWinEventLogSource()
		src.Channels = opts.WindowsChannels
		src.KeepRaw = opts.KeepRaw
		out = append(out, src)
	}
	if opts.Websites {
		out = append(out, NewDNSSource(logger))
	}
	return out
}
