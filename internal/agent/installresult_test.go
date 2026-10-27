package agent

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/Yesveer/wxt-agent/internal/pendinginstall"
)

// sendsLike makes the agent's reporting answer from a script.
func sendsLike(t *testing.T, a *Agent, answers ...bool) *[]installResultPayload {
	t.Helper()
	var sent []installResultPayload
	i := 0
	a.sendInstallResultFn = func(r installResultPayload) bool {
		ok := true
		if i < len(answers) {
			ok = answers[i]
		}
		i++
		if ok {
			sent = append(sent, r)
		}
		return ok
	}
	return &sent
}

func slackInstalled() pendinginstall.MountedDecision {
	return pendinginstall.MountedDecision{App: pendinginstall.MountedApp{
		Name: "Slack", BundleID: "com.tinyspeck.slackmacgap",
		Publisher: "Developer ID Application: SLACK TECHNOLOGIES L.L.C. (BQR82RBBHL)",
	}}
}

// This message is what marks an approval USED. Losing one leaves the
// approval live for the rest of its window, and somebody can uninstall and
// reinstall the software all day without asking anybody — which looks
// exactly like the approval never being spent.
func TestAnInstallReportThatCouldNotBeSentIsSentLater(t *testing.T) {
	a := &Agent{logger: zap.NewNop()}
	sent := sendsLike(t, a, false, true)

	a.reportInstallResult(slackInstalled(), nil)
	if len(*sent) != 0 {
		t.Fatal("the report went out on an attempt that was supposed to fail")
	}

	a.retryUnreportedInstalls()
	if len(*sent) != 1 {
		t.Fatalf("the report was lost: %d sent", len(*sent))
	}
	if (*sent)[0].Application != "Slack" {
		t.Errorf("reported %q", (*sent)[0].Application)
	}
}

// And it keeps waiting while there is still nowhere to send it.
func TestAReportKeepsWaitingUntilItCanBeSent(t *testing.T) {
	a := &Agent{logger: zap.NewNop()}
	sent := sendsLike(t, a, false, false, false, true)

	a.reportInstallResult(slackInstalled(), nil)
	a.retryUnreportedInstalls()
	a.retryUnreportedInstalls()
	if len(*sent) != 0 {
		t.Fatal("something was sent while every attempt was failing")
	}

	a.retryUnreportedInstalls()
	if len(*sent) != 1 {
		t.Errorf("the report was dropped after a few failures: %d sent", len(*sent))
	}
}

// One that got out is not sent twice.
func TestAReportThatWentOutIsNotSentAgain(t *testing.T) {
	a := &Agent{logger: zap.NewNop()}
	sent := sendsLike(t, a, true)

	a.reportInstallResult(slackInstalled(), nil)
	a.retryUnreportedInstalls()
	a.retryUnreportedInstalls()

	if len(*sent) != 1 {
		t.Errorf("sent %d times, wanted once", len(*sent))
	}
}

// A failed install is reported too — an approval that was used and failed is
// a different thing from one nobody acted on.
func TestAFailedInstallIsReportedAsWell(t *testing.T) {
	a := &Agent{logger: zap.NewNop()}
	sent := sendsLike(t, a, true)

	a.reportInstallResult(slackInstalled(), errors.New("no space left on device"))
	if len(*sent) != 1 || (*sent)[0].Problem == "" {
		t.Error("a failed install was not reported, so the approval stays live " +
			"with nothing saying the attempt happened")
	}
}
