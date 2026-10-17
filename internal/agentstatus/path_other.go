//go:build !darwin && !windows

package agentstatus

func platformPath() string { return "/var/log/vsay/status.json" }
