package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Yesveer/wxt-agent/internal/appcontrol"
	"github.com/Yesveer/wxt-agent/internal/appinventory"
	"github.com/Yesveer/wxt-agent/internal/apppolicy"
)

// newPolicyStatusCommand answers "why is my policy not blocking anything?"
// from the machine, in one command.
//
// It exists because every part of that question was previously answerable only
// by someone who could read the source. The portal can say a policy was pushed
// — and the server log does say so — while the endpoint holds a policy in
// audit mode, or one whose rules match nothing installed, or one that was
// never delivered because the machine is not in its scope. Those three look
// identical from the portal and identical to the user, and the difference is
// the whole answer.
//
// Read-only: it decides nothing and changes nothing. It prints what the agent
// is holding and what that policy says about every application on this
// machine, which is exactly the comparison nobody could make by hand.
func newPolicyStatusCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "policy",
		Short: "Show the application policy this machine holds, and what it decides for each installed application",
		RunE: func(cmd *cobra.Command, args []string) error {
			showAll, _ := cmd.Flags().GetBool("all")
			dir, _ := cmd.Flags().GetString("dir")

			eff, path, err := loadStoredPolicy(dir)
			if err != nil {
				fmt.Println("No application policy has reached this machine.")
				fmt.Println()
				fmt.Println("  looked in:", path)
				fmt.Println()
				fmt.Println("That means one of:")
				fmt.Println("  • the agent has never connected since a policy was saved")
				fmt.Println("  • no policy's scope includes this machine")
				fmt.Println("  • this agent is too old to understand application policy")
				fmt.Println()
				fmt.Println("Check the agent log for \"App policy: updated\":")
				fmt.Println("    grep 'App policy' " + defaultLogFile())
				return nil
			}

			printPolicySummary(eff, path)
			return printPolicyDecisions(cmd.Context(), eff, showAll, dir)
		},
	}
	c.Flags().Bool("all", false, "List every application, not only the ones a rule matched")
	c.Flags().String("dir", "", "Where the agent keeps its state (default: the platform's config directory)")
	return c
}

// loadStoredPolicy reads the policy the agent last received.
func loadStoredPolicy(dir string) (*apppolicy.Effective, string, error) {
	if dir == "" {
		dir = appControlStateDir
	}
	path := filepath.Join(dir, "app-policy.json")

	raw, err := os.ReadFile(path) // #nosec G304 -- a path this agent chose
	if err != nil {
		return nil, path, err
	}
	var eff apppolicy.Effective
	if err := json.Unmarshal(raw, &eff); err != nil {
		return nil, path, err
	}
	return &eff, path, nil
}

func printPolicySummary(eff *apppolicy.Effective, path string) {
	fmt.Println("Application policy on this machine")
	fmt.Println()
	fmt.Println("  stored at:      ", path)
	fmt.Println("  agent id:       ", nonEmptyOr(eff.AgentID, "(not set)"))
	fmt.Println("  default action: ", nonEmptyOr(eff.DefaultAction, "allow"))
	fmt.Println("  rules:          ", len(eff.Rules))
	fmt.Println()

	// The single most important line, and the one people guess wrong.
	if eff.Mode == apppolicy.ModeEnforce {
		fmt.Println("  mode:            ENFORCE — matching software is closed and blocked")
	} else {
		fmt.Println("  mode:            AUDIT — matches are reported, NOTHING is blocked")
		fmt.Println()
		fmt.Println("  Two switches must both be on for anything to happen:")
		fmt.Println("    1. the policy's own mode, in the policy editor")
		fmt.Println("    2. Enforcement, at the top of the Policies page")
		fmt.Println("  This machine was sent audit, so at least one of them is off.")
	}
	fmt.Println()

	for i, r := range eff.Rules {
		state := ""
		if !r.Rule.Enabled {
			state = "  (disabled)"
		}
		extra := ""
		if r.RemoveBlocked {
			extra = ", removes matching software"
		}
		fmt.Printf("  #%d %-24s %s  [%s%s]%s\n", i+1, r.Rule.Name, r.Rule.Action, r.PolicyName, extra, state)
		fmt.Println("      " + describeCriteria(r.Rule.Match))
	}
	if len(eff.Rules) == 0 {
		fmt.Println("  No rules reached this machine. Check the policy's \"Applies to\" scope.")
	}
	fmt.Println()
}

// describeCriteria spells out what a rule requires, in the order the engine
// checks it — and says "all of" out loud, because that is the thing people get
// wrong: every field filled in NARROWS the rule.
func describeCriteria(c apppolicy.MatchCriteria) string {
	var parts []string
	add := func(label string, m apppolicy.StringMatch) {
		if m.Empty() {
			return
		}
		parts = append(parts, fmt.Sprintf("%s %s %q", label, nonEmptyOr(m.Op, "equals"), strings.Join(m.Values, "|")))
	}
	add("name", c.AppName)
	add("publisher", c.Publisher)
	add("path", c.FilePath)
	add("bundle-id", c.BundleID)
	if len(c.SHA256) > 0 {
		parts = append(parts, fmt.Sprintf("sha256 one of %d", len(c.SHA256)))
	}
	if len(parts) == 0 {
		return "matches NOTHING — the rule has no conditions"
	}
	return "requires ALL of: " + strings.Join(parts, " AND ")
}

// printPolicyDecisions runs the real policy over the real inventory.
func printPolicyDecisions(ctx context.Context, eff *apppolicy.Effective, showAll bool, dir string) error {
	collector := appinventory.PlatformCollector()
	if collector == nil {
		fmt.Println("No software collector on this platform.")
		return nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	fmt.Println("Scanning installed software…")
	apps, err := collector.Collect(scanCtx)
	if err != nil && len(apps) == 0 {
		return fmt.Errorf("could not read installed software: %w", err)
	}
	fmt.Printf("  %d applications found\n\n", len(apps))

	type row struct{ name, action, rule, path string }
	var matched, all []row

	for _, a := range apps {
		path := a.InstallPath
		if path == "" {
			path = a.ExePath
		}
		d := eff.Evaluate(apppolicy.Program{
			Name: a.Name, Publisher: a.Publisher, Path: path, BundleID: a.BundleID,
		})
		r := row{name: a.Name, action: d.Action, rule: d.Rule, path: path}
		all = append(all, r)
		if d.Rule != "" {
			matched = append(matched, r)
		}
	}

	sort.Slice(matched, func(i, j int) bool { return matched[i].name < matched[j].name })

	if len(matched) == 0 {
		fmt.Println("NO installed application matches any rule.")
		fmt.Println()
		fmt.Println("Every field you fill in on a rule must match at the same time, so an")
		fmt.Println("extra condition makes a rule narrower, not more precise. Compare the")
		fmt.Println("rule conditions above with what this machine actually reports:")
		fmt.Println()
		fmt.Println("    wxt-agent policy --all | head -40")
	} else {
		fmt.Printf("%d application(s) match a rule:\n\n", len(matched))
		for _, r := range matched {
			fmt.Printf("  %-34s → %-7s  by rule %q\n", truncate(r.name, 34), r.action, r.rule)
			fmt.Printf("      %s\n", r.path)
		}
		if eff.Mode != apppolicy.ModeEnforce {
			fmt.Println()
			fmt.Println("  …but the policy is in AUDIT mode, so none of this is acted on.")
		}
	}

	if showAll {
		sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
		fmt.Println()
		fmt.Println("Every application this machine reports, as the policy sees it:")
		fmt.Println()
		for _, r := range all {
			fmt.Printf("  %-38s %-7s %s\n", truncate(r.name, 38), r.action, r.path)
		}
	}

	printHeldApplications(dir)
	return nil
}

// printHeldApplications says what the agent is currently doing to software.
func printHeldApplications(dir string) {
	if dir == "" {
		dir = appControlStateDir
	}
	e := appcontrol.New(appcontrol.Options{StateDir: dir})
	if n := e.HeldCount(); n > 0 {
		fmt.Println()
		fmt.Printf("The agent is currently holding %d application(s) blocked.\n", n)
		fmt.Println("They are restored if the policy changes, and when the agent is uninstalled.")
	}
}

func nonEmptyOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
