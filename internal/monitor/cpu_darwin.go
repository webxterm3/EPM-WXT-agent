//go:build darwin

package monitor

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// cpuPercentFallback measures CPU usage without cgo.
//
// gopsutil reads macOS CPU times through host_processor_info, which is a C
// call: in a CGO_ENABLED=0 build — which is how this agent ships, so that the
// binary is static and needs no Xcode on the endpoint — its darwin
// implementation is a stub returning "not implemented yet". The result was a
// fleet of Macs reporting 0.00 CPU forever, with one warning every 30 seconds
// to say so.
//
// top is used rather than switching the build to cgo because the reading
// should not depend on a build flag being remembered. If this agent is ever
// built with cgo again, gopsutil answers first and this is never reached.
func cpuPercentFallback() (float32, error) {
	// Two samples one second apart: the first is measured from boot and is
	// useless as a current reading. -n 0 lists no processes, which is the
	// expensive part of top.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/top", "-l", "2", "-n", "0", "-s", "1").Output()
	if err != nil {
		return 0, fmt.Errorf("running top: %w", err)
	}

	idle, err := parseTopCPUIdle(string(out))
	if err != nil {
		return 0, err
	}
	return float32(100 - idle), nil
}
