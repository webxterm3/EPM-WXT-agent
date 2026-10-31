package main

import (
	"testing"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
)

// What the agent publishes about work in progress has to reach the menu.
//
// Both halves of this were tested on their own — the agent sets a stage, the
// menu words it — and neither noticed when the field between them was
// dropped. That is the whole feature: a row that never carries its stage
// renders as an ordinary offer, which is the bug all of it exists to fix.
func TestAPublishedStageReachesTheMenu(t *testing.T) {
	for _, stage := range []string{agentstatus.StageChecking, agentstatus.StageInstalling} {
		row := rowFor(agentstatus.PendingInstall{
			Label: "Slack", Path: "/Volumes/Slack/Slack.app", Stage: stage,
		})
		if row.stage != stage {
			t.Errorf("stage %q was dropped on the way to the menu (got %q)",
				stage, row.stage)
		}
	}

	// And a settled row carries none, or every row would look busy.
	if row := rowFor(agentstatus.PendingInstall{
		Label: "Slack", Path: "/Volumes/Slack/Slack.app", Outcome: "installable",
	}); row.stage != "" {
		t.Errorf("a settled row reports stage %q", row.stage)
	}
}
