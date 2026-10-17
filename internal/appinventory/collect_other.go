//go:build !darwin && !windows

package appinventory

import "context"

// PlatformCollector returns nothing on platforms with no collector.
//
// EPM targets Windows and macOS. A Linux build reports that it collects
// nothing rather than appearing to work and producing an empty inventory that
// would read as "this machine has no software installed".
func PlatformCollector() Collector { return nil }

// FastPlatformCollector matches PlatformCollector: there is nothing to make
// faster when there is nothing to collect.
func FastPlatformCollector() Collector { return nil }

// unusedContext keeps the import honest on platforms with no collector.
var _ = context.Background
