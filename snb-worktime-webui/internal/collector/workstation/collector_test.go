package workstation

import (
	"testing"
	"time"
)

func TestBuildActivityWindow(t *testing.T) {
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	window, ok := BuildActivityWindow(Status{
		Server:      "ws-01",
		User:        "alice",
		ClientIP:    "10.0.0.44",
		ClientName:  "WS-01",
		IdleSeconds: 20,
		CapturedAt:  now,
	}, time.Minute, time.Minute)
	if !ok {
		t.Fatal("expected window")
	}
	if !window.StartedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("started_at = %v, want %v", window.StartedAt, now.Add(-time.Minute))
	}
	if window.Source != "workstation-heartbeat" {
		t.Fatalf("source = %q, want workstation-heartbeat", window.Source)
	}
}

func TestBuildActivityWindowSkipsLocked(t *testing.T) {
	_, ok := BuildActivityWindow(Status{
		Server:      "ws-01",
		User:        "alice",
		IdleSeconds: 0,
		Locked:      true,
		CapturedAt:  time.Now().UTC(),
	}, time.Minute, time.Minute)
	if ok {
		t.Fatal("expected locked session to be skipped")
	}
}
