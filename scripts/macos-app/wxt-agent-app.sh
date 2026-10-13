#!/bin/bash
#
# Executable of "/Applications/wxt-agent.app".
#
# ONE application, not three. It was an installer bundle, an uninstaller bundle
# and a status bundle, which meant three things to drag, three names to explain
# and three copies of what "installed" means. This one looks at the machine and
# offers whatever is actually useful: enrol it if it is not enrolled, report on
# it if it is, and remove it either way.
set -u

INSTALL_DIR="@@INSTALL_DIR@@"
CONFIG_DIR="@@CONFIG_DIR@@"
LOG_DIR="@@LOG_DIR@@"
DAEMON_LABEL="@@DAEMON_LABEL@@"

RES="$(cd "$(dirname "$0")/../Resources" && pwd)"
AGENT="$INSTALL_DIR/wxt-agent"

# normalise_command turns a pasted or copied command into one clean line.
#
# The portal shows it across several lines with backslash continuations. A
# dialog field is one line, so those newlines arrive as carriage returns —
# and simply deleting them joins "--token" onto the backslash in front of it,
# producing an argument list that is quietly wrong rather than obviously
# broken. Newlines become spaces, continuation backslashes are dropped, and
# runs of spaces collapse.
normalise_command() {
    printf '%s' "$1" | tr '\r\n' '  ' | sed -e 's/\\ / /g' -e 's/  */ /g' -e 's/^ *//' -e 's/ *$//'
}

# applescript_escape makes a shell string safe to drop inside an AppleScript
# string literal. Without it a command containing a quote — which the portal's
# does, around every value — terminates the literal early and the dialog either
# shows the wrong text or fails to compile.
applescript_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

dialog_error() {
    osascript -e "display dialog \"$1\" with title \"wxt-agent\" buttons {\"OK\"} default button 1 with icon stop" >/dev/null 2>&1
    exit 1
}

# run_privileged <script-body> — one authentication, one temporary file.
#
# The body is written to a file and that file is run, rather than quoting a
# long script through osascript's own escaping as well as the shell's. Escaping
# the same text twice is how an installer ends up running something other than
# what was written.
#
# mktemp -d gives a directory only this user can enter, and the script inside is
# 0700: a file about to run as root must not be writable by anybody else
# between being written and being run.
run_privileged() {
    local work priv
    work="$(mktemp -d)" || { echo "mktemp failed"; return 1; }
    priv="$work/run.sh"
    printf '%s\n' "$1" > "$priv"
    chmod 700 "$priv"
    osascript -e "do shell script \"/bin/bash '$priv'\" with administrator privileges" 2>&1
    local rc=$?
    rm -rf "$work"
    return $rc
}

# ---------------------------------------------------------------- install ----
do_install() {
    # The command box, pre-filled from the clipboard.
    #
    # A REAL text area, not AppleScript's dialog. That dialog's answer field is
    # a single line, and an enrolment command is far longer than it is wide —
    # only the tail was ever visible, so there was no way to see what had been
    # pasted or check it was complete. `wxt-agent prompt-enrolment` puts up an
    # NSTextView instead: it wraps, it scrolls, and the whole command is in
    # front of the person before they press Install.
    local clip enroll
    clip="$(normalise_command "$(pbpaste 2>/dev/null || true)")"
    case "$clip" in
        *configure*) ;;
        # Anything else on the clipboard is somebody's unrelated copy; starting
        # from it would be worse than starting empty.
        *) clip="" ;;
    esac

    # Asked for BEFORE the password prompt: a cancelled paste must not cost
    # somebody an authentication they did not need to give.
    #
    # The binary inside this bundle is used, because nothing is installed yet.
    enroll="$("$RES/wxt-agent" prompt-enrolment --prefill "$clip" 2>/dev/null)" || exit 0

    enroll="$(normalise_command "$enroll")"
    [ -n "$enroll" ] || dialog_error "No enrolment command was entered.\n\nCopy it from the portal, then open wxt-agent again."

    local args
    case "$enroll" in
        *configure*) args="${enroll#*configure}" ;;
        *) dialog_error "That does not look like an enrolment command.\n\nIt must contain the word 'configure'." ;;
    esac

    # The arguments end up in a script that runs as root, so anything that
    # could start a second command is refused. Not a security boundary — the
    # person is authenticating as an administrator and could run anything —
    # but "paste this command" is exactly how somebody gets talked into pasting
    # something else, and an enrolment command never contains these.
    case "$args" in
        *';'*|*'|'*|*'&'*|*'`'*|*'$('*|*'>'*|*'<'*)
            dialog_error "That command contains characters an enrolment command never has (one of ; | & \` \$( > <).\n\nCopy it again from the EPM portal." ;;
    esac

    # The application goes to /Applications FIRST, before the agent is
    # configured and started.
    #
    # The agent looks for its session helper inside the bundle — that is what
    # gives the product ONE row in System Settings instead of two — so the
    # bundle has to be in place before the daemon starts looking. Installing it
    # afterwards left the first session falling back to the loose copy in
    # /usr/local/bin, which is the second row all over again.
    local self
    self="$(cd "$(dirname "$0")/../.." && pwd)"
    APP_DIR_INSTALLED="/Applications/wxt-agent.app"
    case "$self" in
        /Applications/wxt-agent.app) ;;
        *)
            run_privileged "rm -rf '/Applications/wxt-agent.app'
cp -R '$self' '/Applications/wxt-agent.app'
xattr -dr com.apple.quarantine '/Applications/wxt-agent.app' 2>/dev/null || true" >/dev/null 2>&1
            ;;
    esac

    local out
    out=$(run_privileged "set -e
mkdir -p '$INSTALL_DIR' '$CONFIG_DIR/certs' '$LOG_DIR'
cp '$RES/wxt-agent' '$INSTALL_DIR/wxt-agent'

# The session helper is NOT installed here.
#
# It lives inside the application bundle and runs from there, which is what
# gives the product ONE row in System Settings instead of two. A loose copy in
# /usr/local/bin is a second, unbundled program as far as macOS is concerned:
# it gets its own row, with a generic executable icon, and granting one row
# does nothing for the other. Anything an earlier install left there is removed
# for the same reason.
rm -f '$INSTALL_DIR/wxt-agent-session'
chmod 755 '$INSTALL_DIR/wxt-agent'
# A file that arrived through a browser carries com.apple.quarantine, and the
# attribute is copied along with it. Without this the agent is refused as
# coming from an unidentified developer.
xattr -dr com.apple.quarantine '$INSTALL_DIR/wxt-agent' 2>/dev/null || true
'$INSTALL_DIR/wxt-agent' configure $args") || dialog_error "Installation failed.\n\n$(printf '%s' "$out" | tail -c 900)"

    # Put this application in /Applications if it is not already there.
    #
    # Dragging it across is the documented step, but opening it straight from
    # the mounted disk image works too — and then the agent is installed, the
    # image is ejected, and nothing is left in Applications. Copying here means
    # the application is in the one place somebody will look for it, however
    # they started it.
    # Earlier builds installed under other names. Left behind, they sit in
    # Applications with their old icons and read as "the uninstall did not
    # work" — which is exactly how it was reported.
    run_privileged "rm -rf '/Applications/EPM Agent.app' '/Applications/Install EPM Agent.app' '/Applications/Uninstall EPM Agent.app'" >/dev/null 2>&1

    # Make the Privacy & Security rows appear now, while the person is still
    # here.
    #
    # macOS lists a binary under Accessibility or Screen Recording only once it
    # has ASKED for the right, and the agent only asks when somebody first
    # tries to connect. So the rows were missing at exactly the moment the
    # instructions said to switch them on. Run from here it asks in the user's
    # own session, which is where the grant has to land.
    "$APP_DIR_INSTALLED/Contents/MacOS/wxt-agent-session" --check-permissions >/dev/null 2>&1 || true

    osascript <<'OSA' >/dev/null 2>&1
display dialog "wxt-agent is installed and running.

For remote control, macOS needs two permissions it will not grant silently.

ONE entry — wxt-agent — is listed in System Settings › Privacy & Security, under Accessibility and under Screen Recording. Switch it on in both.

You do not need to add any files by hand, and there is nothing else to grant.

The agent restarts itself once both are on." with title "wxt-agent" buttons {"Open Privacy Settings", "Done"} default button "Open Privacy Settings"
if button returned of result is "Open Privacy Settings" then
    open location "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
end if
OSA
}

# ----------------------------------------------------------------- status ----
do_status() {
    local version state enrolled choice
    version="$("$AGENT" version 2>/dev/null | head -1)"
    [ -n "$version" ] || version="unknown"

    # launchctl print succeeds only while the service is actually loaded, which
    # is a stronger statement than "the plist exists".
    if /bin/launchctl print "system/$DAEMON_LABEL" >/dev/null 2>&1; then
        state="Running"
    else
        state="Not running"
    fi

    enrolled="Not enrolled"
    [ -f "$CONFIG_DIR/agent.yaml" ] && enrolled="Enrolled"

    choice=$(osascript <<OSA 2>/dev/null
display dialog "wxt-agent

Status:     $state
Version:    $version
Enrolment:  $enrolled

Installed at: $INSTALL_DIR/wxt-agent
Logs:         $LOG_DIR/agent.log

The agent runs as a background service and does not need to be opened." with title "wxt-agent" buttons {"Re-enrol…", "Check Permissions", "Close"} default button "Close"
button returned of result
OSA
    ) || exit 0

    case "$choice" in
        "Check Permissions") do_check ;;
        # Re-enrolling opens the same command box the first install uses.
        # Without it the box was reachable exactly once, before the agent was
        # installed — so pointing a machine at a different server, or fixing a
        # command that was pasted wrong, meant uninstalling first.
        "Re-enrol…")         do_install ;;
    esac
}

# ------------------------------------------------------------ permissions ----
do_check() {
    # Uninstall lives at the end of this dialog rather than on the main one:
    # three buttons is the most a dialog can carry, and removing the product is
    # the rarest of the things somebody opens this for.
    # Asks the helper, launched the way the agent launches it. A grant is tied
    # to a code signature and evaluated for the process as it is actually
    # started, so this is the only check that answers the real question.
    local out
    out="$("$AGENT" check-permissions 2>&1)"
    local choice
    choice=$(osascript -e "display dialog \"$(printf '%s' "$out" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')\" with title \"wxt-agent — permissions\" buttons {\"Uninstall…\", \"OK\"} default button \"OK\"" -e 'button returned of result' 2>/dev/null) || exit 0
    [ "$choice" = "Uninstall…" ] && do_uninstall
    return 0
}

# -------------------------------------------------------------- uninstall ----
do_uninstall() {
    local choice out
    choice=$(osascript <<OSA 2>/dev/null
display dialog "Remove wxt-agent from this Mac?

This deletes:
    • the background service ($DAEMON_LABEL)
    • $INSTALL_DIR/wxt-agent and wxt-agent-session
    • $CONFIG_DIR (configuration and certificates)
    • $LOG_DIR (logs)
    • its rows in Privacy & Security
    • this application

No user account is touched — this agent never created one.

The machine stays listed in the EPM portal until an administrator removes it there." with title "wxt-agent" buttons {"Cancel", "Remove"} default button "Cancel" with icon caution
button returned of result
OSA
    ) || exit 0
    [ "$choice" = "Remove" ] || exit 0

    # Delegated to the agent's own uninstall command, so there is one
    # description of what "installed" means. When the binary is already gone
    # the files are removed directly: an uninstaller has to finish on a
    # half-removed machine, which is exactly when somebody reaches for it.
    if [ -x "$AGENT" ]; then
        out=$(run_privileged "'$AGENT' uninstall --yes")
    else
        out=$(run_privileged "launchctl bootout system/$DAEMON_LABEL 2>/dev/null || true
rm -f '/Library/LaunchDaemons/$DAEMON_LABEL.plist'
rm -f '$INSTALL_DIR/wxt-agent' '$INSTALL_DIR/wxt-agent-session'
rm -rf '$CONFIG_DIR' '$LOG_DIR' '/Applications/wxt-agent.app'
exit 0")
    fi
    [ $? -eq 0 ] || dialog_error "Uninstall did not complete.\n\n$(printf '%s' "$out" | tail -c 900)"

    osascript <<'OSA' >/dev/null 2>&1
display dialog "wxt-agent has been removed.

Its rows in Privacy & Security were removed too, so a fresh install starts from a clean grant instead of inheriting one recorded against a different build." with title "wxt-agent" buttons {"OK"} default button 1
OSA
}

# ------------------------------------------------------------------- main ----
# Installed or not decides what this app is for. One icon, one name, and
# whichever job actually applies.
if [ -x "$AGENT" ] && [ -f "$CONFIG_DIR/agent.yaml" ]; then
    do_status
else
    do_install
fi
