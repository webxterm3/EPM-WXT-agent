package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Yesveer/wxt-agent/internal/config"
)

// The portal sends exactly these keys. This is the payload the backend builds
// in agentLogShipSettings / sendLogShipPolicy.
const pushedSettings = `{
  "enabled": true,
  "system_logs": true,
  "websites": true,
  "interval_seconds": 60,
  "daily_budget_mb": 512,
  "backfill_hours": 6,
  "include_info_debug": true,
  "keep_raw": true,
  "windows_channels": ["Security", "System"]
}`

// Every field must survive the wire. encoding/json matches field names
// case-insensitively but an underscore defeats that, so without json tags
// "system_logs" would not reach SystemLogs and collection would silently do
// nothing while reporting itself as enabled.
func TestPushedSettingsDecodeCompletely(t *testing.T) {
	var cfg config.LogShippingConfig
	if err := json.Unmarshal([]byte(pushedSettings), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !cfg.Enabled {
		t.Error("Enabled did not decode")
	}
	if !cfg.SystemLogs {
		t.Error("system_logs did not reach SystemLogs")
	}
	if !cfg.Websites {
		t.Error("websites did not reach Websites")
	}
	if cfg.IntervalSeconds != 60 {
		t.Errorf("IntervalSeconds = %d, want 60", cfg.IntervalSeconds)
	}
	if cfg.DailyBudgetMB != 512 {
		t.Errorf("DailyBudgetMB = %d, want 512", cfg.DailyBudgetMB)
	}
	if cfg.BackfillHours != 6 {
		t.Errorf("BackfillHours = %d, want 6", cfg.BackfillHours)
	}
	if !cfg.IncludeInfoDebug {
		t.Error("include_info_debug did not reach IncludeInfoDebug")
	}
	if !cfg.KeepRaw {
		t.Error("keep_raw did not reach KeepRaw")
	}
	if len(cfg.WindowsChannels) != 2 || cfg.WindowsChannels[0] != "Security" {
		t.Errorf("WindowsChannels = %v", cfg.WindowsChannels)
	}
}

// Turning collection off from the portal has to actually turn it off. A
// payload that fails to decode would leave a machine collecting after the
// operator believed they had stopped it.
func TestDisablingDecodes(t *testing.T) {
	var cfg config.LogShippingConfig
	if err := json.Unmarshal([]byte(`{"enabled":false,"system_logs":true}`), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Enabled {
		t.Error("a disable instruction decoded as enabled")
	}
}

func TestLogShipConfigTranslation(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		got := logShipConfig(config.LogShippingConfig{Enabled: true})
		if got.Interval != 30*time.Second {
			t.Errorf("Interval = %s, want the 30s default", got.Interval)
		}
		if got.DailyBudgetBytes != 256<<20 {
			t.Errorf("DailyBudgetBytes = %d, want the 256MiB default", got.DailyBudgetBytes)
		}
		if got.Backfill != 24*time.Hour {
			t.Errorf("Backfill = %s, want the 24h default", got.Backfill)
		}
	})

	t.Run("explicit values", func(t *testing.T) {
		got := logShipConfig(config.LogShippingConfig{
			IntervalSeconds: 120, DailyBudgetMB: 64, BackfillHours: 2,
		})
		if got.Interval != 2*time.Minute {
			t.Errorf("Interval = %s", got.Interval)
		}
		if got.DailyBudgetBytes != 64<<20 {
			t.Errorf("DailyBudgetBytes = %d, want 64MiB", got.DailyBudgetBytes)
		}
		if got.Backfill != 2*time.Hour {
			t.Errorf("Backfill = %s", got.Backfill)
		}
	})

	t.Run("negative budget means unlimited", func(t *testing.T) {
		// Zero already means "use the default", so there has to be some way to
		// say "no ceiling" — otherwise the only way to lift the cap would be to
		// set an absurdly large number.
		got := logShipConfig(config.LogShippingConfig{DailyBudgetMB: -1})
		if got.DailyBudgetBytes != 0 {
			t.Errorf("DailyBudgetBytes = %d, want 0 (unlimited)", got.DailyBudgetBytes)
		}
	})
}

// The bookmark file must not live beside the binary: a package upgrade replaces
// the install directory, and losing the bookmarks would make every machine
// re-ship its whole retained history at once.
func TestBookmarkFileLivesInPersistentState(t *testing.T) {
	if logBookmarkFile == "" {
		t.Fatal("no bookmark path is configured")
	}
	for _, bad := range []string{"/usr/local/bin", "/tmp", `\Program Files`} {
		if len(logBookmarkFile) >= len(bad) && logBookmarkFile[:len(bad)] == bad {
			t.Errorf("bookmarks are stored under %s, which an upgrade or reboot can clear", bad)
		}
	}
}
