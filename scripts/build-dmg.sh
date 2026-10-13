#!/bin/bash
#
# Build the macOS DMG.
#
# The disk image holds ONE application bundle, "wxt-agent.app", beside a link
# to /Applications. Drag it across and open it: it enrols the machine if it is
# not enrolled, and reports on it, checks its permissions or removes it if it
# is.
#
# One rather than three, because an installer bundle, an uninstaller bundle and
# a status bundle meant three things to drag, three names to explain and three
# copies of what "installed" means. Nobody opens a terminal and nobody runs a
# .command file either: macOS opens those in Terminal and asks somebody to
# trust a shell script they cannot read.

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PACKAGE_NAME="wxt-agent"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "1.0.0")}
if [[ ! "$VERSION" =~ ^[0-9] ]]; then
    VERSION="0.0.0-${VERSION}"
fi

DIST_DIR="dist"
BUILD_DIR="$DIST_DIR/dmg"
TEMPLATE_DIR="scripts/macos-app"
ICON_SCRIPT="scripts/icon/make-icon.py"
BUNDLE_PREFIX="${MACOS_BUNDLE_PREFIX:-io.coredge.epm}"
SIGN_ID="${MACOS_SIGN_ID:--}"

# The paths the agent actually installs to. They are substituted into both app
# bundles from here so the installer and the uninstaller cannot drift apart —
# an uninstaller that deletes the wrong path is worse than none.
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/vsay"
LOG_DIR="/var/log/vsay"
DAEMON_LABEL="io.wxt.agent"

echo -e "${GREEN}Building DMG packages${NC}"
echo "Package: $PACKAGE_NAME"
echo "Version: $VERSION"
echo ""

mkdir -p "$BUILD_DIR"

# write_info_plist <contents-dir> <display-name> <bundle-id> <executable>
write_info_plist() {
    cat > "$1/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$2</string>
    <key>CFBundleDisplayName</key><string>$2</string>
    <key>CFBundleIdentifier</key><string>$3</string>
    <key>CFBundleExecutable</key><string>$4</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <!-- No Dock icon: both bundles put up a dialog, do their work and quit. A
         bouncing icon for a three-second task is noise. -->
    <key>LSUIElement</key><true/>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
}

# render_template <source> <destination>
render_template() {
    sed -e "s|@@INSTALL_DIR@@|$INSTALL_DIR|g" \
        -e "s|@@CONFIG_DIR@@|$CONFIG_DIR|g" \
        -e "s|@@LOG_DIR@@|$LOG_DIR|g" \
        -e "s|@@DAEMON_LABEL@@|$DAEMON_LABEL|g" \
        "$1" > "$2"
    chmod +x "$2"
}

create_dmg() {
    local ARCH=$1
    local BIN_SOURCE="$DIST_DIR/bin/darwin-${ARCH}/wxt-agent"
    # The session helper is the half of remote control that runs inside the
    # user's GUI session. Without it the agent still works, but remote control
    # fails at the moment an admin tries to use it.
    local HELPER_SOURCE="$DIST_DIR/bin/darwin-${ARCH}/wxt-agent-session"

    if [ ! -f "$BIN_SOURCE" ]; then
        echo -e "${YELLOW}  Skipping darwin-$ARCH (binary not found)${NC}"
        return
    fi

    local DMG_DIR="$BUILD_DIR/dmg-${ARCH}"
    local STAGE="$DMG_DIR/stage"
    local DMG_NAME="${PACKAGE_NAME}-${VERSION}-macos-${ARCH}.dmg"
    local VOL_NAME="wxt-agent ${VERSION}"

    rm -rf "$DMG_DIR"
    mkdir -p "$STAGE"

    # ONE application. It was an installer bundle, an uninstaller bundle and a
    # status bundle: three things to drag, three names to explain, and three
    # copies of what "installed" means. This one looks at the machine and does
    # whichever job applies.
    local APP="$STAGE/wxt-agent.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    write_info_plist "$APP/Contents" "wxt-agent" "${BUNDLE_PREFIX}.app" "wxt-agent-app"
    render_template "$TEMPLATE_DIR/wxt-agent-app.sh" "$APP/Contents/MacOS/wxt-agent-app"

    cp "$BIN_SOURCE" "$APP/Contents/Resources/wxt-agent"
    chmod +x "$APP/Contents/Resources/wxt-agent"
    if [ -f "$HELPER_SOURCE" ]; then
        cp "$HELPER_SOURCE" "$APP/Contents/Resources/wxt-agent-session"
        chmod +x "$APP/Contents/Resources/wxt-agent-session"

        # The helper ALSO lives inside Contents/MacOS, and that copy is the one
        # that actually runs.
        #
        # macOS attributes a privacy request made by a binary inside an
        # application bundle to the BUNDLE. Run from /usr/local/bin the helper
        # is its own unbundled program, so System Settings lists it separately
        # from the agent — two rows, two switches, for one product. Run from
        # inside the bundle there is one row, named and iconed like the app,
        # and granting it covers everything.
        cp "$HELPER_SOURCE" "$APP/Contents/MacOS/wxt-agent-session"
        chmod +x "$APP/Contents/MacOS/wxt-agent-session"
    else
        echo -e "${YELLOW}  Warning: session helper missing for darwin-$ARCH — remote control will not work${NC}"
    fi

    # Shown in the Dock and Launchpad: this one is meant to be opened.
    /usr/libexec/PlistBuddy -c "Delete :LSUIElement" "$APP/Contents/Info.plist" >/dev/null 2>&1 || true

    # The icon. Generated from scripts/icon/make-icon.py rather than committed
    # as a binary, so the shape and colours are reviewable. Without it macOS
    # draws the blank-page placeholder, which makes a signed, working
    # application look like something that failed to install.
    if python3 "$ICON_SCRIPT" "$DMG_DIR" >/dev/null 2>&1 \
        && iconutil -c icns "$DMG_DIR/wxt-agent.iconset" -o "$APP/Contents/Resources/wxt-agent.icns" >/dev/null 2>&1; then
        /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string wxt-agent" "$APP/Contents/Info.plist" >/dev/null 2>&1
        echo "  ✓ icon"
    else
        echo -e "${YELLOW}  Warning: could not build the icon (needs python3 with Pillow)${NC}"
    fi

    # Signed for the same reason the binaries are: an unsigned bundle has no
    # code identity, so macOS has nothing to key a grant to and Gatekeeper has
    # nothing to check. Ad-hoc unless a Developer ID is supplied.
    if codesign --force --deep --sign "$SIGN_ID" "$APP" >/dev/null 2>&1; then
        echo "  ✓ signed wxt-agent.app"
    else
        echo -e "${YELLOW}  Warning: could not sign wxt-agent.app${NC}"
    fi

    # The /Applications link is what makes this read as an ordinary Mac
    # install: drag across, done.
    ln -s /Applications "$STAGE/Applications"

    cat > "$STAGE/README.txt" << README
wxt-agent ${VERSION} (macOS ${ARCH})

INSTALL
  1. Drag wxt-agent onto the Applications folder.
  2. Open it.
  3. Paste the enrolment command from the EPM portal, then authenticate.

AFTERWARDS
  Opening wxt-agent again shows its status, checks its permissions, or removes it.

PERMISSIONS
Remote control needs two macOS permissions. Once the agent has run, both
wxt-agent entries are LISTED for you in:

    System Settings > Privacy & Security > Accessibility
    System Settings > Privacy & Security > Screen Recording

Switch each one on. You do not need to add any files by hand.

If you are upgrading and an entry is already switched on, remove it with the
minus button and add it again. macOS ties the grant to the exact build it was
given, so an entry left over from an older build stays on while granting
nothing.

ACCOUNTS
This agent does not create user accounts. It works with the accounts already on
the machine.
README

    # A tarball of the SAME bundle, for the terminal install.
    #
    # Built from the identical staged .app rather than assembled separately,
    # so the two ways of installing cannot drift into shipping different
    # software. It exists because macOS marks anything a BROWSER downloads
    # with com.apple.quarantine and Gatekeeper then refuses to open it; curl
    # sets no such mark, so a terminal install never meets Gatekeeper.
    tar -czf "$BUILD_DIR/wxt-agent-macos-${ARCH}.tar.gz" -C "$STAGE" "wxt-agent.app"
    shasum -a 256 "$BUILD_DIR/wxt-agent-macos-${ARCH}.tar.gz" \
        > "$BUILD_DIR/wxt-agent-macos-${ARCH}.tar.gz.sha256"
    echo -e "${GREEN}  ✓ wxt-agent-macos-${ARCH}.tar.gz${NC}"

    hdiutil create -volname "$VOL_NAME" -srcfolder "$STAGE" -ov -format UDZO \
        "$BUILD_DIR/$DMG_NAME" >/dev/null
    shasum -a 256 "$BUILD_DIR/$DMG_NAME" > "$BUILD_DIR/$DMG_NAME.sha256"
    rm -rf "$DMG_DIR"

    echo -e "${GREEN}  ✓ $DMG_NAME${NC}"
}

create_dmg "amd64"
create_dmg "arm64"

echo ""
echo -e "${GREEN}DMG packages built${NC}"
ls -la "$BUILD_DIR"/*.dmg 2>/dev/null || true
