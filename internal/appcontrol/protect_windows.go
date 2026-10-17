//go:build windows

package appcontrol

// protectedPrefixes are the parts of Windows that enforcement never touches.
//
// C:/Windows covers the operating system itself. The two Program Files
// entries are NOT protected: that is where the software an operator actually
// writes policy about is installed.
var protectedPrefixes = []string{
	"c:/windows",
	"c:/programdata/microsoft/windows/start menu",
	"c:/program files/windows defender",
	"c:/program files (x86)/windows defender",
}

// ownInstallPaths are where this product's own files live on Windows.
var ownInstallPaths = []string{
	`C:\ProgramData\vsay`,
	`C:\Program Files\vsay`,
}
