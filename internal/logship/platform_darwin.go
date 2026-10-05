//go:build darwin

package logship

import "go.uber.org/zap"

// PlatformSources builds the collectors available on macOS.
func PlatformSources(opts SourceOptions, logger *zap.Logger) []Source {
	var out []Source

	if opts.SystemLogs {
		out = append(out, &UnifiedLogSource{
			IncludeInfoDebug: opts.IncludeInfoDebug,
			KeepRaw:          opts.KeepRaw,
		})
	}
	if opts.Websites {
		out = append(out, NewDNSSource(logger))
	}
	return out
}
