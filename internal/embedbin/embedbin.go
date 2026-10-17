// Package embedbin writes an executable that was embedded in another one.
//
// Shared by helperbin and traybin: the agent carries two programs inside
// itself, and both face the same two problems when writing one out — a
// running executable cannot be overwritten in place, and rewriting an
// unchanged one churns the file for nothing (and on macOS risks invalidating
// the privacy grant somebody already gave it).
//
// One copy of that, rather than two that drift.
package embedbin

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// ExtractTo writes data to path as an executable.
//
// An existing file with identical contents is left alone. Anything else is
// replaced, which is how an agent upgrade carries a new copy with it.
func ExtractTo(path string, data []byte) (string, error) {
	if same, err := sameContents(path, data); err == nil && same {
		return path, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- the install dir is readable by design
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	// Write to a temporary file and rename into place. A direct write over a
	// running helper fails outright on Windows ("file in use") and, on Unix,
	// would corrupt the image of a process still executing it.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil { // #nosec G306 -- it has to be executable
		return "", fmt.Errorf("writing %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		// Windows refuses to rename over a file that is currently executing.
		// Removing it first is allowed there (the running image survives), so
		// retry that way before giving up.
		if rmErr := os.Remove(path); rmErr == nil {
			if err2 := os.Rename(tmp, path); err2 == nil {
				return path, nil
			}
		}
		_ = os.Remove(tmp)
		return "", fmt.Errorf("installing %s: %w", path, err)
	}
	return path, nil
}

// sameContents reports whether the file at path is byte-identical to data.
func sameContents(path string, data []byte) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	// Size is checked first so a mismatched file costs one stat, not a full
	// read of several megabytes.
	if info.Size() != int64(len(data)) {
		return false, nil
	}

	onDisk, err := os.ReadFile(path) // #nosec G304 -- path is the agent's own install location
	if err != nil {
		return false, err
	}
	return bytes.Equal(onDisk, data), nil
}
