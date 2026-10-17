//go:build windows

package agentstatus

import (
	"os"
	"path/filepath"
)

func platformPath() string {
	dir := `C:\ProgramData\vsay\logs`
	if pd := os.Getenv("ProgramData"); pd != "" {
		dir = filepath.Join(pd, "vsay", "logs")
	}
	return filepath.Join(dir, "status.json")
}
