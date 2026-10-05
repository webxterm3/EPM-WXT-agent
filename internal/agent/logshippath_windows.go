//go:build windows

package agent

// logBookmarkFile mirrors the Unix layout under ProgramData. See the Unix file
// for why it lives outside the binary's directory.
var logBookmarkFile = `C:\ProgramData\vsay\logship\bookmarks.json`
