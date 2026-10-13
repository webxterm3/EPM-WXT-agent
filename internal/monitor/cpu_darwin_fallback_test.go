package monitor

import "testing"

// The second sample is the live one. The first is measured from boot, so
// reading it reports the machine's lifetime average — a number that looks
// plausible and never moves.
func TestIdleComesFromTheLastSample(t *testing.T) {
	out := `Processes: 600 total
CPU usage: 2.00% user, 3.00% sys, 95.00% idle
Processes: 600 total
CPU usage: 10.00% user, 15.00% sys, 75.00% idle
`
	idle, err := parseTopCPUIdle(out)
	if err != nil {
		t.Fatal(err)
	}
	if idle != 75 {
		t.Errorf("idle = %v, want 75 (the second sample)", idle)
	}
}

func TestBusyIsTheComplementOfIdle(t *testing.T) {
	idle, err := parseTopCPUIdle("CPU usage: 4.76% user, 9.52% sys, 85.71% idle")
	if err != nil {
		t.Fatal(err)
	}
	if busy := 100 - idle; busy < 14.2 || busy > 14.3 {
		t.Errorf("busy = %v, want ~14.29", busy)
	}
}

// A machine doing nothing must read 0%, not 100%. Getting the sense of this
// backwards is the obvious way to break it and looks fine at a glance.
func TestAnIdleMachineReadsZero(t *testing.T) {
	idle, err := parseTopCPUIdle("CPU usage: 0.00% user, 0.00% sys, 100.00% idle")
	if err != nil {
		t.Fatal(err)
	}
	if busy := 100 - idle; busy != 0 {
		t.Errorf("an idle machine reported %v%% busy", busy)
	}
}

// Returning 0 with no error would be indistinguishable from a genuinely idle
// machine, which is exactly the failure being fixed.
func TestUnparseableOutputIsAnError(t *testing.T) {
	for _, out := range []string{"", "Processes: 600 total", "CPU usage: nonsense"} {
		if _, err := parseTopCPUIdle(out); err == nil {
			t.Errorf("no error for %q — a parse failure would read as 0%% busy", out)
		}
	}
}
