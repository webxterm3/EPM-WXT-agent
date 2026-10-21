package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Yesveer/wxt-agent/internal/agentstatus"
)

// The menu is read at a glance. time.Duration's own String gives "2h14m9.3s",
// which is precise and unreadable at the speed somebody opens a menu bar.
func TestAnAgeReadsAtAGlance(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want string
	}{
		{3 * time.Second, "3s"},
		{59 * time.Second, "59s"},
		{90 * time.Second, "1m"},
		{59 * time.Minute, "59m"},
		{time.Hour, "1h"},
		{2*time.Hour + 14*time.Minute, "2h 14m"},
		{25 * time.Hour, "1d 1h"},
		{48 * time.Hour, "2d"},
		{10 * 24 * time.Hour, "10d"},
	} {
		if got := shortDuration(c.in); got != c.want {
			t.Errorf("shortDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// An agent built before ConnectedSince existed reports connected without
// saying since when. Showing "connected · 0s" for a machine that has been up
// for a week is worse than showing no duration at all — it is a wrong answer
// where there could have been none.
func TestNoStartTimeMeansNoDurationIsClaimed(t *testing.T) {
	if got := connectedFor(agentstatus.Status{Connected: true}); got != "" {
		t.Errorf("claimed a duration of %q with no start time recorded", got)
	}
}

// Two clocks are involved: the agent writes the file, the menu bar reads it.
// A machine whose agent runs slightly ahead would otherwise show a negative
// age, which renders as "connected · -4s".
func TestAClockRunningAheadDoesNotProduceANegativeAge(t *testing.T) {
	ahead := agentstatus.Status{Connected: true, ConnectedSince: time.Now().Add(30 * time.Second)}
	if got := connectedFor(ahead); got != "" {
		t.Errorf("got %q — a start time in the future must produce no duration", got)
	}
}

func TestAConnectionDurationIsShown(t *testing.T) {
	st := agentstatus.Status{Connected: true, ConnectedSince: time.Now().Add(-2 * time.Hour)}
	got := connectedFor(st)
	if !strings.Contains(got, "2h") {
		t.Errorf("got %q, want something containing 2h", got)
	}
	if !strings.HasPrefix(got, " · ") {
		t.Errorf("got %q — it is appended to the headline and needs its separator", got)
	}
}

// The policy line answers a different question to the connection line, and
// goes stale at a completely different rate. A machine can be connected for a
// week and hold a policy from a month ago.
func TestThePolicyLineDistinguishesNeverFromNotYet(t *testing.T) {
	offline := policyLine(agentstatus.Status{}, false)
	online := policyLine(agentstatus.Status{}, true)

	if offline == online {
		t.Error("an agent that has never synced and one that has just connected " +
			"report the same thing, though only the second is about to")
	}
	for _, s := range []string{offline, online} {
		if !strings.Contains(strings.ToLower(s), "polic") {
			t.Errorf("%q does not say what it is about", s)
		}
	}
}

// Zero rules is a real state — a policy arrived and says nothing about
// anything. Left unnamed it renders as a missing clause and reads as a fault.
func TestAPolicyWithNoRulesSaysSo(t *testing.T) {
	st := agentstatus.Status{PolicySyncedAt: time.Now().Add(-time.Minute), PolicyRules: 0}
	got := policyLine(st, true)
	if !strings.Contains(got, "no rules") {
		t.Errorf("got %q — a policy with nothing in it must say so", got)
	}
}

func TestThePolicyLineReportsRulesAndMode(t *testing.T) {
	st := agentstatus.Status{
		PolicySyncedAt: time.Now().Add(-5 * time.Minute),
		PolicyRules:    3,
		PolicyMode:     "enforce",
	}
	got := policyLine(st, true)
	for _, want := range []string{"5m", "3 rules", "enforce"} {
		if !strings.Contains(got, want) {
			t.Errorf("policy line %q does not mention %q", got, want)
		}
	}

	one := policyLine(agentstatus.Status{PolicySyncedAt: time.Now(), PolicyRules: 1}, true)
	if strings.Contains(one, "1 rules") {
		t.Errorf("got %q — one rule is not 1 rules", one)
	}
}

// The headline is the one line somebody reads. It must name the product and
// say the state in plain words, because the coloured dot beside it is the only
// other signal and a dot alone means nothing on first sight.
func TestTheHeadlineNamesTheProductAndTheState(t *testing.T) {
	_, title, _, _ := currentState()
	if !strings.Contains(title, "wxt-agent") {
		t.Errorf("headline %q does not name the product", title)
	}
	if strings.HasSuffix(title, ":") {
		t.Errorf("headline %q ends mid-sentence", title)
	}
}
