//go:build darwin

package pendinginstall

import "testing"

// Real pkgutil output, measured on this platform.
const (
	signedPkg = `Package "signed.pkg":
   Status: signed by a certificate trusted on this system
   Certificate Chain:
    1. IntuneMDMAgent-91cc02b4-96b1-4d3d-afd2-e4599c8ac52f
       Expires: 2027-04-03 22:44:52 +0000
    2. Microsoft Intune MDM Agent CA
`
	unsignedPkg = `Package "probe.pkg":
   Status: no signature
`
	untrustedPkg = `Package "odd.pkg":
   Status: signed by untrusted certificate
   Certificate Chain:
    1. Somebody's Own Certificate Authority
`
)

func TestASignedPackageNamesItsSigner(t *testing.T) {
	if got := signerFrom(signedPkg); got != "IntuneMDMAgent-91cc02b4-96b1-4d3d-afd2-e4599c8ac52f" {
		t.Errorf("signer %q — the FIRST chain entry is the signer; the ones "+
			"after it are the authorities above it", got)
	}
}

// A package runs as root and may do anything. An unsigned one has no
// identity at all, so there is nothing for policy to match and nothing an
// approver could be approving.
func TestAnUnsignedPackageHasNoSigner(t *testing.T) {
	if got := signerFrom(unsignedPkg); got != "" {
		t.Errorf("an unsigned package reported %q as its signer", got)
	}
}

// "signed by untrusted certificate" contains "signed by" and is not a
// signature anybody should act on — and this one runs as root.
func TestAnUntrustedSignatureIsNotASignature(t *testing.T) {
	if got := signerFrom(untrustedPkg); got != "" {
		t.Errorf("an untrusted certificate was accepted as the signer: %q", got)
	}
}

// Nothing recognisable is not a signature either.
func TestUnreadableOutputIsNotASignature(t *testing.T) {
	for _, out := range []string{"", "pkgutil: command not found", "Package \"x\":\n"} {
		if got := signerFrom(out); got != "" {
			t.Errorf("read %q as a signer from %q", got, out)
		}
	}
}
