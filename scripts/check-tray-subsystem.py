#!/usr/bin/env python3
"""Fail the build if the Windows tray program would open a console window.

Go builds a CONSOLE application on Windows by default. Built that way the tray
opened a terminal of its own — and because that window owned the process,
closing it removed the icon from the notification area. `-H windowsgui` is the
only thing standing between the shipped binary and that behaviour, and it is a
single flag in a Makefile line that nobody would think to check.

PE optional-header Subsystem: 2 = Windows GUI, 3 = console.
"""

import struct
import sys


def subsystem(path: str) -> int:
    with open(path, "rb") as f:
        head = f.read(1024)
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    # Optional header begins at pe+24; Subsystem sits 68 bytes into it.
    return struct.unpack_from("<H", head, pe + 24 + 68)[0]


def main(paths):
    bad = False
    for p in paths:
        try:
            s = subsystem(p)
        except Exception as e:  # noqa: BLE001 - any malformed file is a failure
            print(f"  ✗ {p}: could not read the PE header: {e}")
            bad = True
            continue
        if s != 2:
            print(f"  ✗ {p}: subsystem {s}, expected 2 (Windows GUI).")
            print("    Built like this it opens a console window, and closing")
            print("    that window kills the tray icon. Build it with")
            print("    $(TRAY_WIN_LDFLAGS), which carries -H windowsgui.")
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
