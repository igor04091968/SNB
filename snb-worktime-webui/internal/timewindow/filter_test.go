package timewindow

import (
	"testing"
	"time"
)

func TestDurationWithDayWindow(t *testing.T) {
	start := time.Date(2026, 4, 19, 8, 30, 0, 0, time.UTC)
	end := time.Date(2026, 4, 19, 10, 30, 0, 0, time.UTC)

	got := Duration(start, end, time.Time{}, time.Time{}, 9*60, 10*60)
	if got != time.Hour {
		t.Fatalf("Duration() = %v, want 1h", got)
	}
}
