//go:build !darwin && !windows

package logship

import "go.uber.org/zap"

// PlatformSources returns nothing on platforms with no collector.
//
// The shipper treats an empty source list as "disabled" and says so once at
// startup, so a Linux build reports that it collects nothing rather than
// appearing to work and producing an empty archive.
func PlatformSources(_ SourceOptions, _ *zap.Logger) []Source { return nil }
