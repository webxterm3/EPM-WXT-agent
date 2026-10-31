//go:build !darwin

package pendinginstall

// Progress reporting follows the install it describes, and installing from a
// mounted disk image is a macOS idea.

type Progress struct {
	Phase       string
	Done, Total int64
}

func SetProgressSink(func(Progress)) {}
