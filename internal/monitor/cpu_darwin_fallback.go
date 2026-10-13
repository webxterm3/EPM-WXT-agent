package monitor

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTopCPUIdle pulls the idle percentage out of top's CPU line.
//
// The line looks like:
//
//	CPU usage: 4.76% user, 9.52% sys, 85.71% idle
//
// Idle is read rather than user+sys because those two do not account for
// everything on every macOS version, and busy-from-idle is exact either way.
//
// top prints one such line per sample; the LAST one is taken. The first sample
// is measured from boot, so using it would report a machine's lifetime average
// and never move again.
func parseTopCPUIdle(out string) (float64, error) {
	idle := -1.0

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "CPU usage:") {
			continue
		}
		for _, field := range strings.Split(strings.TrimPrefix(line, "CPU usage:"), ",") {
			field = strings.TrimSpace(field)
			if !strings.HasSuffix(field, "idle") {
				continue
			}
			value := strings.TrimSpace(strings.TrimSuffix(field, "idle"))
			value = strings.TrimSuffix(value, "%")
			// Locales that use a comma as the decimal separator would have
			// been split apart above; nothing sensible can be recovered from
			// the pieces, so such a line is simply skipped.
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				continue
			}
			idle = parsed
		}
	}

	if idle < 0 {
		return 0, fmt.Errorf("no CPU usage line in top output")
	}
	if idle > 100 {
		idle = 100
	}
	return idle, nil
}
