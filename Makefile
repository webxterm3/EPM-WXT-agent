.PHONY: help build build-all install clean test lint proto proto-install
.PHONY: build-linux build-macos build-windows
.PHONY: build-deb build-rpm build-dmg build-exe build-tar
.PHONY: packages all deploy-binaries macos-signing-identity

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "1.0.0")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) -extldflags '-static'"

# The session helper cannot be linked statically on macOS: it needs cgo for
# ScreenCaptureKit, CGEvent and NSPasteboard, and Apple does not ship the static
# crt0.o that -static requires. These flags are the same minus -static.
HELPER_LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# The session helper carries an Info.plist INSIDE the Mach-O, and claims the
# application's own bundle identifier.
#
# This is what makes macOS ask for ONE permission instead of several. Without a
# bundle identifier a bare executable is a TCC client keyed by its file path,
# listed under its file name with a blank "exec" icon — and every copy of it,
# at every path, is a different client needing its own grant. People ended up
# with three rows called wxt-agent, none of which was the one doing the asking.
#
# With the identifier, the helper and /Applications/wxt-agent.app are the same
# code identity: one row, named and iconed like the product, and `tccutil reset
# io.coredge.epm.app` can clear it — which it could not before, because
# tccutil resolves bundle identifiers through LaunchServices and a bare
# binary's signing identifier is not one.
MACOS_APP_ID     ?= $(MACOS_BUNDLE_PREFIX).app
MACOS_HELPER_PLIST := $(abspath build/macos/session-helper-info.plist)
MACOS_HELPER_LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) -extldflags -Wl,-sectcreate,__TEXT,__info_plist,$(MACOS_HELPER_PLIST)"

# The Windows tray program is a GUI-subsystem binary.
#
# -H windowsgui is not cosmetic. Go builds a CONSOLE application by default, so
# the tray opened a terminal window of its own — and because that window OWNED
# the process, closing it killed the icon. A notification-area program has no
# console and must not have one.
TRAY_WIN_LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) -H windowsgui"

# The agent embeds the session helper so that each platform ships as ONE file.
# //go:embed reads from this fixed path, so the helper for a given target is
# built into it immediately before the agent for that same target — the two
# builds cannot be reordered or parallelised.
EMBED_SLOT := internal/remotecontrol/helperbin/helper.bin

# The agent also carries the status-area program (menu bar on macOS, tray on
# Windows), for the same reason: it ships as ONE downloadable file, and a
# second executable that has to arrive beside it does not.
TRAY_SLOT := internal/traybin/tray.bin

# Directories
DIST_DIR := dist
BIN_DIR := $(DIST_DIR)/bin
AGENT_BACKEND_DIR ?= ../vsay-agent-backend

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# MAIN TARGETS
# =============================================================================

all: packages ## Build everything (all platforms, all packages)

packages: build-all build-deb build-rpm build-tar build-dmg build-exe ## Build every package format, Linux included

packages-desktop: build-dmg build-exe ## Build only the platforms EPM supports (macOS, Windows)

# The embed slot (see EMBED_SLOT) is shared mutable state: each target writes
# the helper for its own platform into the same file before building the agent.
# A parallel make would interleave those writes and embed the wrong helper, so
# this Makefile must run serially.
.NOTPARALLEL:

# =============================================================================
# PROTO GENERATION
# =============================================================================

proto: ## Generate protobuf code
	@echo "Generating protobuf code..."
	@chmod +x scripts/generate-proto.sh
	@./scripts/generate-proto.sh

proto-install: ## Install protobuf tools
	@echo "Installing protobuf tools..."
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "✓ Tools installed. Install protoc from: https://grpc.io/docs/protoc-installation/"

# =============================================================================
# BUILD BINARIES
# =============================================================================

build: proto ## Build for current platform
	@echo "Building wxt-agent for current platform..."
	@go build $(LDFLAGS) -o wxt-agent ./cmd/agent
	@echo "✓ Built: wxt-agent"
	@go build $(HELPER_LDFLAGS) -o wxt-agent-session ./cmd/session-helper
	@echo "✓ Built: wxt-agent-session"

build-all: proto build-linux build-macos build-windows ## Build binaries for all platforms
	@echo ""
	@echo "✓ All binaries built successfully!"
	@ls -la $(BIN_DIR)/

build-linux: proto ## Build for Linux (amd64, arm64)
	@echo "Building for Linux..."
	@mkdir -p $(BIN_DIR)/linux-amd64 $(BIN_DIR)/linux-arm64
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/linux-amd64/wxt-agent ./cmd/agent
	@echo "  ✓ linux-amd64"
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/linux-arm64/wxt-agent ./cmd/agent
	@echo "  ✓ linux-arm64"

# check_embedded_helper <built-helper> — the embedded copy must be byte-identical.
#
# Checked at the one moment it can be: after the agent is built and before the
# slot is reset. The agent writes its embedded helper out at runtime whenever
# the file on disk differs, so a mismatch here means every agent start
# overwrites the installed helper, changes its code identity, and invalidates
# the macOS permission grants — a permission that is granted, verified as
# granted, and refused again minutes later.
#
# It is a hard failure. The build that produces it looks perfectly fine and
# ships a product whose remote control cannot be permitted.
define check_embedded_helper
	@if ! cmp -s "$(EMBED_SLOT)" "$(1)"; then \
		echo ""; \
		echo "  ✗ the embedded session helper differs from $(1)"; \
		echo "    The agent would rewrite the installed helper on every start,"; \
		echo "    invalidating its macOS permission grants."; \
		echo "    Sign the helper BEFORE copying it into the embed slot."; \
		exit 1; \
	fi
endef

# sign_macos_binary <path> — ad-hoc unless MACOS_SIGN_ID names a real identity.
#
# Called inline rather than as one pass at the end, because WHEN a binary is
# signed matters: the session helper must be signed BEFORE it is embedded into
# the agent. See the comment in build-macos.
# sign_macos_identified <path> <identifier> — sign with an identifier chosen by
# the caller rather than derived from the file name.
define sign_macos_identified
	@opts=""; [ "$(MACOS_SIGN_ID)" = "-" ] || opts="--options runtime"; \
	codesign --force --timestamp=none $$opts $(MACOS_KEYCHAIN_ARG) \
		--identifier "$(2)" \
		--sign "$(MACOS_SIGN_ID)" "$(1)" >/dev/null 2>&1 \
		|| echo "  ✗ $(1) — codesign failed (macOS + Xcode CLT required)"
	$(call check_stable_signature,$(1))
endef

# check_helper_identity <path> — every darwin binary must claim the
# APPLICATION's identifier, or the single-permission property is silently gone.
#
# Nothing else would notice. The build succeeds, the agent runs, remote control
# works on the developer's machine where the grant is already in place — and
# every new install asks for a separate permission under a nameless row.
#
# All three binaries, not just the helper. macOS records a privacy grant
# against the RESPONSIBLE process — the topmost launchd-started ancestor of
# whoever calls the API, which launchctl asuser does not reset — so the daemon
# and the menu bar item end up at the head of chains that ask, even though
# neither contains a single TCC symbol. One identity for the whole product is
# what makes those land on one row.
define check_helper_identity
	@id="$$(codesign -d --verbose=2 "$(1)" 2>&1 | sed -n 's/^Identifier=//p')"; \
	if [ "$$id" != "$(MACOS_APP_ID)" ]; then \
		echo ""; \
		echo "✗ $(1) claims identifier \"$$id\""; \
		echo "  It must claim \"$(MACOS_APP_ID)\" — the application's own identifier —"; \
		echo "  or macOS lists it as a separate program needing its own permission."; \
		exit 1; \
	fi
	@if ! otool -s __TEXT __info_plist "$(1)" >/dev/null 2>&1; then \
		echo "✗ $(1) has no embedded Info.plist; macOS would list it as a bare executable"; \
		exit 1; \
	fi
endef

define sign_macos_binary
	@opts=""; [ "$(MACOS_SIGN_ID)" = "-" ] || opts="--options runtime"; \
	codesign --force --timestamp=none $$opts $(MACOS_KEYCHAIN_ARG) \
		--identifier "$(MACOS_BUNDLE_PREFIX).$(notdir $(1))" \
		--sign "$(MACOS_SIGN_ID)" "$(1)" >/dev/null 2>&1 \
		|| echo "  ✗ $(1) — codesign failed (macOS + Xcode CLT required)"
	$(call check_stable_signature,$(1))
endef

build-macos: proto ## Build for macOS (amd64, arm64)
	@echo "Building for macOS..."
	@mkdir -p $(BIN_DIR)/darwin-amd64 $(BIN_DIR)/darwin-arm64
	@# BOTH binaries are built with cgo on macOS, and HELPER_LDFLAGS (no
	@# -static) is used for both — Apple ships no static crt0.o.
	@#
	@# The agent needs cgo for two things that are only reachable through C:
	@# registering itself in System Settings › Privacy & Security, and reading
	@# CPU times. Built without it, neither fails loudly — the agent simply
	@# never appears in the permission lists, and CPU reads 0% forever. Both
	@# have a fallback for safety, but the fallback is not the plan.
	@#
	@# The session helper MUST be built with cgo: screen capture is
	@# ScreenCaptureKit, input is CGEvent and the clipboard is NSPasteboard,
	@# none of which exist without it. Cross-arch therefore needs an explicit
	@# -arch for the C compiler, and both builds need macOS + Xcode CLT.
	@# Helper first, SIGNED, and only then embedded into the agent.
	@#
	@# The order is load-bearing. The agent carries the helper inside itself
	@# and writes it out at runtime when the file on disk differs. Sign the
	@# helper AFTER embedding and the two copies differ for ever: every start
	@# rewrites /usr/local/bin/wxt-agent-session with the embedded one, the
	@# binary's code identity changes, and macOS treats the Accessibility and
	@# Screen Recording grants as belonging to a program that no longer
	@# exists. The symptom is a permission that is granted, verified as
	@# granted, and refused again a minute later.
	@CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-arch x86_64" CGO_LDFLAGS="-arch x86_64" \
		go build $(MACOS_HELPER_LDFLAGS) -o $(BIN_DIR)/darwin-amd64/wxt-agent-session ./cmd/session-helper
	$(call sign_macos_identified,$(BIN_DIR)/darwin-amd64/wxt-agent-session,$(MACOS_APP_ID))
	$(call check_helper_identity,$(BIN_DIR)/darwin-amd64/wxt-agent-session)
	@echo "  ✓ darwin-amd64 session helper (signed)"
	@cp $(BIN_DIR)/darwin-amd64/wxt-agent-session $(EMBED_SLOT)
	@# The menu bar item, built and signed BEFORE the agent for the same
	@# reason the helper is: the agent embeds it, and the embedded copy
	@# must be byte-identical to the one on disk or every start rewrites
	@# the installed file.
	@CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-arch x86_64" CGO_LDFLAGS="-arch x86_64" \
		go build $(HELPER_LDFLAGS) -o $(BIN_DIR)/darwin-amd64/wxt-agent-menubar ./cmd/menubar
	$(call sign_macos_identified,$(BIN_DIR)/darwin-amd64/wxt-agent-menubar,$(MACOS_APP_ID))
	$(call check_helper_identity,$(BIN_DIR)/darwin-amd64/wxt-agent-menubar)
	@echo "  ✓ darwin-amd64 menu bar item (signed)"
	@cp $(BIN_DIR)/darwin-amd64/wxt-agent-menubar $(TRAY_SLOT)
	@CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-arch x86_64" CGO_LDFLAGS="-arch x86_64" \
		go build $(HELPER_LDFLAGS) -o $(BIN_DIR)/darwin-amd64/wxt-agent ./cmd/agent
	$(call sign_macos_identified,$(BIN_DIR)/darwin-amd64/wxt-agent,$(MACOS_APP_ID))
	$(call check_helper_identity,$(BIN_DIR)/darwin-amd64/wxt-agent)
	$(call check_embedded_helper,$(BIN_DIR)/darwin-amd64/wxt-agent-session)
	@echo "  ✓ darwin-amd64 (signed, helper embedded, verified)"
	@CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-arch arm64" CGO_LDFLAGS="-arch arm64" \
		go build $(MACOS_HELPER_LDFLAGS) -o $(BIN_DIR)/darwin-arm64/wxt-agent-session ./cmd/session-helper
	$(call sign_macos_identified,$(BIN_DIR)/darwin-arm64/wxt-agent-session,$(MACOS_APP_ID))
	$(call check_helper_identity,$(BIN_DIR)/darwin-arm64/wxt-agent-session)
	@echo "  ✓ darwin-arm64 session helper (signed)"
	@cp $(BIN_DIR)/darwin-arm64/wxt-agent-session $(EMBED_SLOT)
	@# The menu bar item, built and signed BEFORE the agent for the same
	@# reason the helper is: the agent embeds it, and the embedded copy
	@# must be byte-identical to the one on disk or every start rewrites
	@# the installed file.
	@CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-arch arm64" CGO_LDFLAGS="-arch arm64" \
		go build $(HELPER_LDFLAGS) -o $(BIN_DIR)/darwin-arm64/wxt-agent-menubar ./cmd/menubar
	$(call sign_macos_identified,$(BIN_DIR)/darwin-arm64/wxt-agent-menubar,$(MACOS_APP_ID))
	$(call check_helper_identity,$(BIN_DIR)/darwin-arm64/wxt-agent-menubar)
	@echo "  ✓ darwin-arm64 menu bar item (signed)"
	@cp $(BIN_DIR)/darwin-arm64/wxt-agent-menubar $(TRAY_SLOT)
	@CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-arch arm64" CGO_LDFLAGS="-arch arm64" \
		go build $(HELPER_LDFLAGS) -o $(BIN_DIR)/darwin-arm64/wxt-agent ./cmd/agent
	$(call sign_macos_identified,$(BIN_DIR)/darwin-arm64/wxt-agent,$(MACOS_APP_ID))
	$(call check_helper_identity,$(BIN_DIR)/darwin-arm64/wxt-agent)
	$(call check_embedded_helper,$(BIN_DIR)/darwin-arm64/wxt-agent-session)
	@echo "  ✓ darwin-arm64 (signed, helper embedded, verified)"
	@$(MAKE) --no-print-directory reset-embed-slot

# Signing identity.
#
# Three tiers, worst to best:
#
#   ad-hoc ("-")      the fallback. Its designated requirement is the hash of
#                     the binary, so EVERY rebuild invalidates every macOS
#                     privacy grant the product has been given. The switch in
#                     System Settings stays on and the permission stops
#                     applying, which reads as the product being broken.
#
#   self-signed       `make macos-signing-identity`, once. The requirement
#                     becomes identifier-plus-certificate, which survives
#                     rebuilds — so an upgrade keeps its grants. Gatekeeper
#                     still refuses it.
#
#   Developer ID      make build-macos MACOS_SIGN_ID="Developer ID Application: Acme (TEAMID)"
#                     Everything above, plus Gatekeeper and notarization.
#
# The self-signed identity is picked up automatically when it exists, because a
# build that silently falls back to ad-hoc is a build that silently breaks
# everybody's permissions.
MACOS_SIGN_KEYCHAIN ?= $(HOME)/.wxt-agent/signing.keychain-db
MACOS_SIGN_CN       ?= EPM Agent Code Signing
MACOS_SIGN_ID       ?= $(shell [ -f "$(MACOS_SIGN_KEYCHAIN)" ] && \
	security find-identity -p codesigning "$(MACOS_SIGN_KEYCHAIN)" 2>/dev/null \
	| grep -q "$(MACOS_SIGN_CN)" && echo "$(MACOS_SIGN_CN)" || echo "-")
MACOS_BUNDLE_PREFIX ?= io.coredge.epm

# codesign needs telling which keychain holds the key; it does not search one
# that is not on the user's search list, and adding it to the search list would
# be a side effect on the developer's machine.
MACOS_KEYCHAIN_ARG = $(if $(filter -,$(MACOS_SIGN_ID)),,--keychain "$(MACOS_SIGN_KEYCHAIN)")

macos-signing-identity: ## Create the local signing identity (once) so grants survive rebuilds
	@./scripts/macos-signing-identity.sh

# check_stable_signature <path> — fails the build if a configured identity did
# not actually produce a rebuild-proof requirement.
#
# The whole point of the identity is the shape of this string. If signing
# quietly fell back to ad-hoc — an expired certificate, a locked keychain, a
# renamed identity — the binaries still build, still run, and still throw away
# every permission grant on the fleet. Nothing else would notice.
define check_stable_signature
	@if [ "$(MACOS_SIGN_ID)" != "-" ]; then \
		req="$$(codesign -d -r- "$(1)" 2>&1 | grep '^designated' || true)"; \
		case "$$req" in \
			*certificate*) ;; \
			*) echo ""; \
			   echo "✗ $(1) is signed with a per-build identity:"; \
			   echo "    $$req"; \
			   echo "  Every macOS permission grant on every machine would be"; \
			   echo "  invalidated by this build. Check the signing keychain:"; \
			   echo "    $(MACOS_SIGN_KEYCHAIN)"; \
			   exit 1;; \
		esac; \
	fi
endef

sign-macos: ## Code-sign the macOS binaries (ad-hoc by default)
	@echo "Signing macOS binaries (identity: $(MACOS_SIGN_ID))..."
	@# Why this step is not optional.
	@#
	@# On Apple Silicon the Go linker ad-hoc signs arm64 binaries by itself,
	@# so those at least carry a cdhash. CROSS-COMPILED amd64 binaries get
	@# nothing at all — "code object is not signed at all" — and an unsigned
	@# binary has no code identity for macOS to key a TCC grant to. The
	@# Accessibility and Screen Recording toggles then show as ON in System
	@# Settings while AXIsProcessTrusted() keeps returning false, which is
	@# indistinguishable from the product being broken.
	@#
	@# --identifier matters too: the linker's default is "a.out" for every
	@# binary, so the agent and its helper claim the SAME identity. Each gets
	@# its own here, because TCC lists them separately and the user has to be
	@# able to tell which row is which.
	@# The hardened runtime is applied ONLY with a real Developer ID.
	@#
	@# It is meaningless on an ad-hoc signature — there is nothing to harden
	@# against without notarization — and it changes how macOS treats the
	@# binary. TCC is the part that matters: Accessibility and Screen Recording
	@# are granted against a code signature, and an unusual ad-hoc-plus-hardened
	@# combination is not worth the risk of the grant quietly not applying to
	@# the process that asks for it.
	@opts=""; [ "$(MACOS_SIGN_ID)" = "-" ] || opts="--options runtime"; \
	for arch in amd64 arm64; do \
		for bin in wxt-agent; do \
			f="$(BIN_DIR)/darwin-$$arch/$$bin"; \
			[ -f "$$f" ] || continue; \
			codesign --force --timestamp=none $$opts $(MACOS_KEYCHAIN_ARG) \
				--identifier "$(MACOS_BUNDLE_PREFIX).$$bin" \
				--sign "$(MACOS_SIGN_ID)" "$$f" >/dev/null 2>&1 \
				&& echo "  ✓ darwin-$$arch/$$bin" \
				|| echo "  ✗ darwin-$$arch/$$bin — codesign failed (macOS + Xcode CLT required)"; \
		done; \
	done
	@if [ "$(MACOS_SIGN_ID)" = "-" ]; then \
		echo ""; \
		echo "  ⚠  Signed ad-hoc. Every macOS privacy grant this build is given"; \
		echo "     will stop applying the next time these binaries are rebuilt."; \
		echo "     Run 'make macos-signing-identity' once to fix that."; \
	else \
		echo "  ✓ grants will survive a rebuild (identity: $(MACOS_SIGN_ID))"; \
		echo "  Note: a self-signed identity does NOT satisfy Gatekeeper."; \
		echo "  Distribution still needs a Developer ID and notarization."; \
	fi

build-windows: proto ## Build for Windows (amd64, arm64)
	@echo "Building for Windows..."
	@mkdir -p $(BIN_DIR)/windows-amd64 $(BIN_DIR)/windows-arm64
	@# The Windows helper is plain syscalls against user32/gdi32, so unlike the
	@# macOS one it needs no cgo and cross-compiles from anywhere.
	@# Helper first, then embedded into the agent for the same arch.
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/windows-amd64/wxt-agent-session.exe ./cmd/session-helper
	@echo "  ✓ windows-amd64 session helper"
	@cp $(BIN_DIR)/windows-amd64/wxt-agent-session.exe $(EMBED_SLOT)
	@# The tray icon, built BEFORE the agent so the agent can embed it.
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(TRAY_WIN_LDFLAGS) -o $(BIN_DIR)/windows-amd64/wxt-agent-tray.exe ./cmd/menubar
	@echo "  ✓ windows-amd64 tray icon"
	@cp $(BIN_DIR)/windows-amd64/wxt-agent-tray.exe $(TRAY_SLOT)
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/windows-amd64/wxt-agent.exe ./cmd/agent
	@echo "  ✓ windows-amd64 (helper embedded)"
	@CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/windows-arm64/wxt-agent-session.exe ./cmd/session-helper
	@echo "  ✓ windows-arm64 session helper"
	@cp $(BIN_DIR)/windows-arm64/wxt-agent-session.exe $(EMBED_SLOT)
	@# The tray icon, built BEFORE the agent so the agent can embed it.
	@CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(TRAY_WIN_LDFLAGS) -o $(BIN_DIR)/windows-arm64/wxt-agent-tray.exe ./cmd/menubar
	@echo "  ✓ windows-arm64 tray icon"
	@cp $(BIN_DIR)/windows-arm64/wxt-agent-tray.exe $(TRAY_SLOT)
	@CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/windows-arm64/wxt-agent.exe ./cmd/agent
	@echo "  ✓ windows-arm64 (helper embedded)"
	@# A console-subsystem tray opens a terminal window that owns the
	@# process, so closing it removes the icon. One flag stands between
	@# the shipped binary and that, and it is worth checking.
	@python3 scripts/check-tray-subsystem.py $(BIN_DIR)/windows-amd64/wxt-agent-tray.exe $(BIN_DIR)/windows-arm64/wxt-agent-tray.exe
	@echo "  ✓ tray binaries are GUI subsystem (no console window)"
	@$(MAKE) --no-print-directory reset-embed-slot

# =============================================================================
# PACKAGE BUILDS
# =============================================================================

build-deb: build-linux ## Build DEB packages (Debian/Ubuntu) for amd64 and arm64
	@echo ""
	@echo "Building DEB packages..."
	@mkdir -p $(DIST_DIR)/deb
	@# Skip rather than fail when no packaging tool is installed. EPM targets
	@# Windows and macOS, and a dev machine without dpkg/nfpm must still be
	@# able to run the full deploy for those.
	@if command -v nfpm >/dev/null 2>&1 || command -v dpkg-deb >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then \
		ARCH=amd64 VERSION=$(VERSION) ./scripts/build-deb.sh && \
		ARCH=arm64 VERSION=$(VERSION) ./scripts/build-deb.sh && \
		echo "✓ DEB packages built"; \
	else \
		echo "  ⊘ skipped — no nfpm, dpkg-deb or docker on this machine"; \
	fi

build-rpm: build-linux ## Build RPM packages (RHEL/CentOS/Rocky/Fedora) for amd64 and arm64
	@echo ""
	@echo "Building RPM packages..."
	@mkdir -p $(DIST_DIR)/rpm
	@if command -v nfpm >/dev/null 2>&1 || command -v rpmbuild >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then \
		ARCH=amd64 VERSION=$(VERSION) ./scripts/build-rpm.sh && \
		ARCH=arm64 VERSION=$(VERSION) ./scripts/build-rpm.sh && \
		echo "✓ RPM packages built"; \
	else \
		echo "  ⊘ skipped — no nfpm, rpmbuild or docker on this machine"; \
	fi

build-tar: build-linux build-macos ## Build TAR.GZ packages (Universal) for all platforms
	@echo ""
	@echo "Building TAR.GZ packages..."
	@mkdir -p $(DIST_DIR)/tar
	@./scripts/build-tar.sh
	@echo "✓ TAR.GZ packages built"

build-dmg: build-macos ## Build DMG packages (macOS) for amd64 and arm64
	@echo ""
	@echo "Building DMG packages..."
	@mkdir -p $(DIST_DIR)/dmg
	@MACOS_SIGN_ID="$(MACOS_SIGN_ID)" MACOS_SIGN_KEYCHAIN="$(MACOS_SIGN_KEYCHAIN)" ./scripts/build-dmg.sh
	@echo "✓ DMG packages built"

build-exe: build-windows ## Build Windows installers (EXE) for amd64 and arm64
	@echo ""
	@echo "Building Windows packages..."
	@mkdir -p $(DIST_DIR)/windows
	@./scripts/build-windows.sh
	@echo "✓ Windows packages built"

reset-embed-slot: ## Restore the embed placeholder (run automatically after builds)
	@printf '%s\n' \
		'WXT-HELPER-PLACEHOLDER' \
		'This file is a build-time placeholder, not a binary.' \
		'' \
		'//go:embed cannot compile against a file that does not exist, so one has to be' \
		'committed. The Makefile overwrites it with the real session helper for the' \
		'target platform immediately before building the agent, which is what makes the' \
		'agent a single self-contained download.' \
		'' \
		'An agent built without that step embeds THIS text. helperbin.Available()' \
		'detects it by the marker on the first line and reports that nothing usable is' \
		'embedded, so the agent falls back to looking for the helper on disk rather than' \
		'extracting garbage and failing in a way nobody could diagnose.' \
		> $(EMBED_SLOT)
	@printf '%s\n' \
		'WXT-TRAY-PLACEHOLDER' \
		'This file is a build-time placeholder, not a binary.' \
		'' \
		'The same arrangement as helper.bin, for the status-area program: the Makefile' \
		'overwrites it with the real menu bar / tray binary for the target platform' \
		'immediately before building the agent, which is what lets the agent install it' \
		'from a single downloaded file.' \
		'' \
		'An agent built without that step embeds THIS text. traybin.Available() detects' \
		'it by the marker on the first line, so configure falls back to looking for a' \
		'copy on disk rather than writing garbage and failing unreadably.' \
		> $(TRAY_SLOT)

# =============================================================================
# UTILITIES
# =============================================================================

install: build ## Build and install agent locally
	@echo "Installing wxt-agent..."
	@sudo cp wxt-agent /usr/local/bin/
	@sudo chmod +x /usr/local/bin/wxt-agent
	@echo "✓ Installed to /usr/local/bin/wxt-agent"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -f wxt-agent wxt-agent.exe
	@rm -rf $(DIST_DIR)/
	@echo "✓ Cleaned"

test: ## Run tests
	@echo "Running tests..."
	@go test ./...

lint: ## Run linter
	@echo "Running linter..."
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

run: build ## Build and run agent
	@./wxt-agent start --config config.yaml

dev: ## Run in development mode
	@go run cmd/agent/main.go start --config config.yaml

# =============================================================================
# RELEASE
# =============================================================================

deploy-binaries: packages-desktop ## Build macOS + Windows packages and copy to vsay-agent-backend/agent-binaries/
	@echo ""
	@echo "Deploying packages to $(AGENT_BACKEND_DIR)/agent-binaries/..."
	@mkdir -p $(AGENT_BACKEND_DIR)/agent-binaries
	@# Only macOS and Windows: those are the platforms remote control runs on.
	@# Linux machines are managed through the terminal and have no desktop to
	@# take over, so publishing a Linux agent here would advertise a feature it
	@# cannot provide.
	@f=$$(ls -t $(DIST_DIR)/dmg/wxt-agent-*-macos-amd64.dmg 2>/dev/null | head -1) && [ -n "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/wxt-agent-amd64.dmg && echo "  ✓ wxt-agent-amd64.dmg" || echo "  ✗ wxt-agent-amd64.dmg not found (macOS only)"
	@f=$$(ls -t $(DIST_DIR)/dmg/wxt-agent-*-macos-arm64.dmg 2>/dev/null | head -1) && [ -n "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/wxt-agent-arm64.dmg && echo "  ✓ wxt-agent-arm64.dmg" || echo "  ✗ wxt-agent-arm64.dmg not found (macOS only)"
	@f=$$(ls -t $(DIST_DIR)/windows/wxt-agent_*_windows_amd64.exe 2>/dev/null | head -1) && [ -n "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/wxt-agent-amd64.exe && echo "  ✓ wxt-agent-amd64.exe" || echo "  ✗ wxt-agent-amd64.exe not found"
	@f=$$(ls -t $(DIST_DIR)/windows/wxt-agent_*_windows_arm64.exe 2>/dev/null | head -1) && [ -n "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/wxt-agent-arm64.exe && echo "  ✓ wxt-agent-arm64.exe" || echo "  ✗ wxt-agent-arm64.exe not found"
	@# The terminal-install artefacts: a tarball of the same .app bundle the
	@# disk image ships, and the script that fetches it. Needed because macOS
	@# quarantines anything a browser downloads and Gatekeeper then refuses to
	@# open it; curl marks nothing, so this path never meets Gatekeeper.
	@f=$$(ls -t $(DIST_DIR)/dmg/wxt-agent-macos-amd64.tar.gz 2>/dev/null | head -1) && [ -n "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/ && echo "  ✓ wxt-agent-macos-amd64.tar.gz" || echo "  ✗ wxt-agent-macos-amd64.tar.gz not found (macOS only)"
	@f=$$(ls -t $(DIST_DIR)/dmg/wxt-agent-macos-arm64.tar.gz 2>/dev/null | head -1) && [ -n "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/ && echo "  ✓ wxt-agent-macos-arm64.tar.gz" || echo "  ✗ wxt-agent-macos-arm64.tar.gz not found (macOS only)"
	@cp scripts/install-macos.sh $(AGENT_BACKEND_DIR)/agent-binaries/install-macos.sh && chmod +x $(AGENT_BACKEND_DIR)/agent-binaries/install-macos.sh && echo "  ✓ install-macos.sh"
	@echo ""
	@echo "(session helper is bundled inside each agent binary — no separate download)"
	@echo "macOS standalone agent binaries (for curl installs)..."
	@f=$(BIN_DIR)/darwin-amd64/wxt-agent; [ -f "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/wxt-agent-macos-amd64 && echo "  ✓ wxt-agent-macos-amd64" || echo "  ✗ wxt-agent-macos-amd64 not found"
	@f=$(BIN_DIR)/darwin-arm64/wxt-agent; [ -f "$$f" ] && cp "$$f" $(AGENT_BACKEND_DIR)/agent-binaries/wxt-agent-macos-arm64 && echo "  ✓ wxt-agent-macos-arm64" || echo "  ✗ wxt-agent-macos-arm64 not found"
	@echo ""
	@echo "✓ Deploy complete!"
	@ls -lh $(AGENT_BACKEND_DIR)/agent-binaries/ | grep -v gitkeep

release: clean packages ## Build release packages
	@echo ""
	@echo "=============================================="
	@echo "Release packages built successfully!"
	@echo "=============================================="
	@echo ""
	@echo "DEB packages (Debian/Ubuntu):"
	@ls -la $(DIST_DIR)/deb/*.deb 2>/dev/null || echo "  (none)"
	@echo ""
	@echo "RPM packages (RHEL/CentOS/Rocky/Fedora):"
	@ls -la $(DIST_DIR)/rpm/*.rpm 2>/dev/null || echo "  (none)"
	@echo ""
	@echo "TAR.GZ packages (Universal):"
	@ls -la $(DIST_DIR)/tar/*.tar.gz 2>/dev/null || echo "  (none)"
	@echo ""
	@echo "DMG packages (macOS):"
	@ls -la $(DIST_DIR)/dmg/*.dmg 2>/dev/null || echo "  (none)"
	@echo ""
	@echo "Windows packages:"
	@ls -la $(DIST_DIR)/windows/*.zip 2>/dev/null || echo "  (none)"
