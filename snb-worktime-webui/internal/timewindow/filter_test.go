package timewindow

import (
	"testing"
	"time"
)

func TestDurationWithDayWindow(t *testing.T) {
	start := time.Date(2026, 4, 19, 8, 30, 0, 0, time.UTC)
	end := time.Date(2026, 4, 19, 10, 30, 0, 0, time.UTC)

	got := Duration(start, end, time.Time{}, time.Time{}, 9*60, 10*60, time.UTC)
	if got != time.Hour {
		t.Fatalf("Duration() = %v, want 1h", got)
	}
}

func TestSegmentsWithLocalDayWindow(t *testing.T) {
	previousLocal := time.Local
	t.Cleanup(func() { time.Local = previousLocal })
	time.Local = time.FixedZone("MSK", 3*60*60)

	start := time.Date(2026, 4, 18, 5, 42, 0, 0, time.UTC)
	end := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 17, 21, 0, 0, 0, time.UTC)
	until := time.Date(2026, 4, 19, 21, 0, 0, 0, time.UTC)

	segments := Segments(start, end, since, until, 8*60+30, 17*60+30, time.Local)
	if len(segments) != 2 {
		t.Fatalf("Segments() returned %d segments, want 2", len(segments))
	}

	if got := segments[0].Start.In(time.Local).Format("2006-01-02 15:04"); got != "2026-04-18 08:42" {
		t.Fatalf("first segment start = %s, want 2026-04-18 08:42", got)
	}
	if got := segments[0].End.In(time.Local).Format("2006-01-02 15:04"); got != "2026-04-18 17:30" {
		t.Fatalf("first segment end = %s, want 2026-04-18 17:30", got)
	}
	if got := segments[1].Start.In(time.Local).Format("2006-01-02 15:04"); got != "2026-04-19 08:30" {
		t.Fatalf("second segment start = %s, want 2026-04-19 08:30", got)
	}
	if got := segments[1].End.In(time.Local).Format("2006-01-02 15:04"); got != "2026-04-19 17:30" {
		t.Fatalf("second segment end = %s, want 2026-04-19 17:30", got)
	}
}
