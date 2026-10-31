//go:build !darwin

package main

import "time"

// The progress panel is macOS-only, because the install flow it narrates is.
//
// Windows software installs through its own installer, which draws its own
// progress; the agent is not standing between somebody and a disk image
// there, so there is nothing for a panel of ours to say that the installer
// is not already saying better.
//
// Stubs rather than build tags around every call site: the wording, the
// ordering and the re-entrancy guard in software.go are shared logic worth
// keeping in one piece, and wrapping each of its four calls in a build
// constraint would be four more places for the platforms to drift.

func progressShow(title, body string) {}
func progressHide()                   {}
func progressUpdate(float64, string)  {}

// pumpRunLoop has no interface to keep alive here, so it waits.
//
// Sleeping is exactly what the macOS version must NOT do — it would freeze
// the panel it is waiting for — but with no panel there is nothing to
// freeze, and the caller still needs the time to pass.
func pumpRunLoop(d time.Duration) { time.Sleep(d) }
