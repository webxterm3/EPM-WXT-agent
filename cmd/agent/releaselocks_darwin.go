//go:build darwin

package main

// appControlStateDir is where the enforcer records what it has locked: beside
// the agent's configuration, which is where the policy it enforces also lives.
const appControlStateDir = "/etc/vsay"
