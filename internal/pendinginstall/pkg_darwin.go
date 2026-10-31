//go:build darwin

package pendinginstall

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Installer packages.
//
// A .pkg is not a folder somebody drags: it is a program that runs as root
// and may do anything. So the signature is not a label here, it is the whole
// of the trust decision, and an unsigned package is refused outright rather
// than offered for approval — no approver can supply a signature, and saying
// yes to "install this unsigned thing as root" is not a decision anybody
// should be asked to make from a menu.

// pkgStatus is the line pkgutil prints about a package's signature:
//
//	Status: signed by a certificate trusted on this system
//	Status: no signature
var pkgStatus = regexp.MustCompile(`(?m)^\s*Status:\s*(.+?)\s*$`)

// pkgSigner is the first entry of the certificate chain, which is the signer.
// The ones after it are the authorities above it.
//
//  1. IntuneMDMAgent-91cc02b4-…
var pkgSigner = regexp.MustCompile(`(?m)^\s*1\.\s*(.+?)\s*$`)

// verifiedPackageSigner returns who signed a package, or empty when nothing
// vouches for it.
//
// BOTH the exit code and the Status line have to agree.
//
// Measured on this platform: an unsigned package exits 1 and prints
// "Status: no signature"; a signed one exits 0 and prints "Status: signed
// by …". Neither is relied on alone — a tool that changes which of the two
// carries the answer would otherwise silently start approving unsigned
// packages, and this one runs them as root.
var verifiedPackageSigner = func(pkg string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/sbin/pkgutil",
		"--check-signature", pkg).CombinedOutput()
	if err != nil {
		return ""
	}

	return signerFrom(string(out))
}

// signerFrom reads pkgutil's answer. Split out so the parsing can be tested
// against real output without a package to point at.
func signerFrom(out string) string {
	status := ""
	if m := pkgStatus.FindStringSubmatch(out); m != nil {
		status = strings.ToLower(m[1])
	}
	// "signed by untrusted certificate" contains "signed by" and is not a
	// signature anybody should act on.
	if !strings.Contains(status, "signed by") || strings.Contains(status, "untrusted") {
		return ""
	}

	m := pkgSigner.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// installPackage runs an installer package, as root, against this machine.
//
// `-target /` is the whole system, which is what a package expects and what
// every installer somebody double-clicks does. There is no narrower target
// that means anything: a package decides for itself where its payload goes.
var installPackage = func(pkg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// -verboseR, so the installer says how far along it is.
	//
	// It is the only honest source for a package. A package decides for
	// itself where its payload goes and runs scripts of its own, so there
	// is no directory to watch growing the way a bundle copy can be
	// watched — anything measured from outside would be a guess.
	//
	// Measured on this platform, the lines are:
	//
	//	installer:PHASE:Preparing the disk…
	//	installer:%97.750000
	//	installer:PHASE:The software was successfully installed.
	//
	// Output is still collected in full, because when this fails the whole
	// of it is the only explanation anybody gets.
	cmd := exec.CommandContext(ctx, "/usr/sbin/installer",
		"-verboseR", "-pkg", pkg, "-target", "/")

	out, err := runWithProgress(cmd)
	if err != nil {
		return &installerError{pkg: pkg, detail: strings.TrimSpace(out), err: err}
	}
	return nil
}

// installerPercent and installerPhase are what -verboseR prints.
var (
	installerPercent = regexp.MustCompile(`^installer:%([0-9.]+)`)
	installerPhase   = regexp.MustCompile(`^installer:PHASE:(.+)$`)
)

// runWithProgress runs the installer, reporting each percentage it prints
// and returning everything it said.
//
// Percentages are scaled to a fixed 10000 rather than reported as a float,
// because the channel to the menu bar carries two integers — done out of
// total — and that is the shape a copy needs. A package is simply a copy
// whose total is a constant.
func runWithProgress(cmd *exec.Cmd) (string, error) {
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return "", err
	}

	// Carried between lines, and LOCAL to this run.
	//
	// A phase line arrives without a percentage and a percentage without a
	// phase, so each has to keep what the other last said — otherwise the
	// bar drops to zero every time the words change. Package-level would
	// have been one line shorter and would have started the next install
	// at the previous one's percentage.
	var (
		lastPhase   string
		lastPercent int64
	)

	var collected strings.Builder
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()
		collected.WriteString(line)
		collected.WriteString("\n")

		if m := installerPhase.FindStringSubmatch(line); m != nil {
			lastPhase = strings.TrimSpace(m[1])
			// A phase with no percentage yet still moves the words, which
			// is what the early part of a package install consists of.
			report(Progress{Phase: lastPhase, Done: lastPercent, Total: percentScale})
			continue
		}
		if m := installerPercent.FindStringSubmatch(line); m != nil {
			if v, convErr := strconv.ParseFloat(m[1], 64); convErr == nil {
				lastPercent = int64(v / 100 * percentScale)
				report(Progress{Phase: lastPhase, Done: lastPercent, Total: percentScale})
			}
		}
	}

	waitErr := cmd.Wait()
	return collected.String(), waitErr
}

// percentScale is what a package's progress is counted out of.
//
// The channel to the menu bar carries two integers, done out of total,
// because that is the shape a file copy has. A package reports a percentage
// instead, so it is expressed as a fraction of a constant.
const percentScale = 10000

type installerError struct {
	pkg    string
	detail string
	err    error
}

func (e *installerError) Error() string {
	if e.detail != "" {
		return "installing " + e.pkg + ": " + e.detail
	}
	return "installing " + e.pkg + ": " + e.err.Error()
}

func (e *installerError) Unwrap() error { return e.err }
