package web

import (
	"testing"
	"time"

	"snb-worktime-webui/internal/model"
)

func TestApplyDateIntervalFiltersUsesLocalDates(t *testing.T) {
	previousLocal := time.Local
	t.Cleanup(func() { time.Local = previousLocal })
	time.Local = time.FixedZone("MSK", 3*60*60)

	cfg := model.Config{}
	if err := applyDateIntervalFilters(&cfg, "2026-04-18", "2026-04-19", "08:30", "17:30"); err != nil {
		t.Fatalf("applyDateIntervalFilters() error = %v", err)
	}

	if got := cfg.Since.In(time.Local).Format("2006-01-02 15:04"); got != "2026-04-18 00:00" {
		t.Fatalf("cfg.Since local = %s, want 2026-04-18 00:00", got)
	}
	if got := cfg.Until.In(time.Local).Format("2006-01-02 15:04"); got != "2026-04-20 00:00" {
		t.Fatalf("cfg.Until local = %s, want 2026-04-20 00:00", got)
	}
	if cfg.DayStartMinutes != 8*60+30 || cfg.DayEndMinutes != 17*60+30 {
		t.Fatalf("unexpected day window: %d-%d", cfg.DayStartMinutes, cfg.DayEndMinutes)
	}
}
