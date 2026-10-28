//go:build darwin

package pendinginstall

import (
	"context"
	"os/exec"
	"regexp"
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

	out, err := exec.CommandContext(ctx, "/usr/sbin/installer",
		"-pkg", pkg, "-target", "/").CombinedOutput()
	if err != nil {
		return &installerError{pkg: pkg, detail: strings.TrimSpace(string(out)), err: err}
	}
	return nil
}

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
