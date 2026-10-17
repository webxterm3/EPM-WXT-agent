#!/usr/bin/env bash
#
# Create (once) a code-signing identity whose grants survive a rebuild.
#
# WHY THIS EXISTS
#
# An ad-hoc signature — codesign --sign - — produces a designated requirement
# that is the HASH OF THE BINARY:
#
#     designated => cdhash H"24e2eb913c505ad2d38ac7323f0055773400e7e6"
#
# macOS records a privacy grant together with that requirement. Rebuild the
# binary, the hash changes, and the stored grant no longer matches the thing
# asking — so Accessibility shows the switch ON and AXIsProcessTrusted() keeps
# returning false. That is indistinguishable from a broken product, and it is
# exactly what people hit after every upgrade.
#
# Signed with a certificate instead, the requirement becomes:
#
#     designated => identifier "io.coredge.epm.wxt-agent-session"
#                   and certificate leaf = H"f9a76f31…"
#
# which says nothing about the binary's contents. Rebuild as often as you like:
# the grant still applies.
#
# This is NOT a substitute for a Developer ID. The certificate is self-signed,
# so Gatekeeper still refuses the download and notarization is still the thing
# that fixes that. It solves one specific problem — grants that evaporate on
# upgrade — and it solves it completely.
#
# WHAT IT IS NOT
#
# The key is not a secret worth protecting. It signs nothing anybody trusts;
# its only power is to make a requirement string stable. It lives in its own
# keychain rather than the login keychain so that building never prompts for,
# or has access to, anything of the developer's.

set -euo pipefail

KEYCHAIN_DIR="${WXT_SIGNING_DIR:-$HOME/.wxt-agent}"
KEYCHAIN="$KEYCHAIN_DIR/signing.keychain-db"
KEYCHAIN_PASSWORD="wxt-agent"
IDENTITY_CN="EPM Agent Code Signing"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# --- already there? -------------------------------------------------------

if [ -f "$KEYCHAIN" ] && security find-identity -p codesigning "$KEYCHAIN" 2>/dev/null | grep -q "$IDENTITY_CN"; then
    echo -e "${GREEN}✓${NC} signing identity already exists"
    echo "  keychain: $KEYCHAIN"
    echo "  identity: $IDENTITY_CN"
    exit 0
fi

echo "Creating a code-signing identity for stable macOS permission grants…"
mkdir -p "$KEYCHAIN_DIR"
chmod 700 "$KEYCHAIN_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# codeSigning in extendedKeyUsage is what makes codesign accept the identity at
# all; without it the certificate imports fine and is then invisible to
# find-identity, which is a confusing half-hour for whoever hits it.
cat > "$WORK/req.cnf" <<CNF
[ req ]
distinguished_name = dn
prompt             = no
x509_extensions    = v3
[ dn ]
CN = $IDENTITY_CN
O  = EPM
[ v3 ]
basicConstraints     = critical,CA:false
keyUsage             = critical,digitalSignature
extendedKeyUsage     = critical,codeSigning
CNF

openssl req -x509 -newkey rsa:2048 -nodes -days 7300 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -config "$WORK/req.cnf" 2>/dev/null

# -legacy and -macalg sha1: macOS's keychain importer cannot read a PKCS#12
# written with OpenSSL 3's defaults, and fails with "MAC verification failed
# (wrong password?)" — which sends you looking at the password instead.
openssl pkcs12 -export -legacy -macalg sha1 \
    -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
    -out "$WORK/identity.p12" -passout "pass:$KEYCHAIN_PASSWORD" \
    -name "$IDENTITY_CN" 2>/dev/null

rm -f "$KEYCHAIN"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
# No automatic relock: a keychain that locks itself mid-build turns one failed
# signature into a build that works in the morning and not in the afternoon.
security set-keychain-settings "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

security import "$WORK/identity.p12" -k "$KEYCHAIN" \
    -P "$KEYCHAIN_PASSWORD" -T /usr/bin/codesign -A >/dev/null

# Without this, every codesign call puts up a "wants to use a key" panel — on a
# build machine that is a prompt nobody is sitting in front of.
security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null 2>&1 || true

if ! security find-identity -p codesigning "$KEYCHAIN" 2>/dev/null | grep -q "$IDENTITY_CN"; then
    echo "✗ the identity was created but codesign cannot see it" >&2
    exit 1
fi

echo -e "${GREEN}✓${NC} created"
echo "  keychain: $KEYCHAIN"
echo "  identity: $IDENTITY_CN"
echo
echo -e "${YELLOW}Note:${NC} this certificate is self-signed. It makes permission grants"
echo "  survive rebuilds; it does NOT satisfy Gatekeeper. Distribution still"
echo "  needs a Developer ID and notarization."
