package agent

import (
	"strings"
	"testing"
)

func TestTheInstallPathAsksWhetherItMayAct(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) rescanVolumes", "\nfunc "))
	if !strings.Contains(body, "eff.Enforcing()") {
		t.Error("rescanVolumes does not ask whether the policy may act, so a " +
			"policy in audit mode still ejects disk images")
	}
}
