package agent

import (
	"strings"
	"testing"
)

func TestAMountedRowCarriesWhetherTheAskWentOut(t *testing.T) {
	body := codeOnly(sourceBetween(t, readSource(t, "internal/agent/pendinginstall.go"),
		"func (a *Agent) publishMounted", "\nfunc "))
	if !strings.Contains(body, "state.refused[volume].requested") {
		t.Error("a mounted row reports 'not yet asked' unconditionally, so " +
			"re-opening the image asks the same question from the start")
	}
}
