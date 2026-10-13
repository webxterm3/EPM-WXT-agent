//go:build !darwin

package main

import "fmt"

// reportPermissions exists on every platform so --check-permissions is never
// simply missing: a flag that vanishes on one platform reads as a broken build
// rather than as "nothing to check here".
func reportPermissions() int {
	fmt.Println("Only macOS gates screen capture and input behind a permission the user must grant.")
	fmt.Println("On this platform there is nothing to check.")
	return 0
}
