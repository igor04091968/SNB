package worktime

import (
	"strings"
	"testing"
	"time"

	"snb-worktime-webui/internal/model"
	"snb-worktime-webui/internal/parser"
)

func TestSummarize(t *testing.T) {
	snapshots, warnings, err := parser.ParseSnapshotsJSONL(strings.NewReader(sampleSnapshots))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	windows, warnings, err := parser.ParseActivityWindowsJSONL(strings.NewReader(sampleWindows))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	rows := Summarize(snapshots, windows, model.Config{
		ActiveIdleThreshold: time.Minute,
		MaxGap:              10 * time.Minute,
	})

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	alice := rows[0]
	if alice.User != "alice" {
		t.Fatalf("unexpected first row: %+v", alice)
	}
	if alice.WorkedMinutes != 5 {
		t.Fatalf("alice worked minutes = %d, want 5", alice.WorkedMinutes)
	}
	if alice.ConfirmedMinutes != 3 {
		t.Fatalf("alice confirmed minutes = %d, want 3", alice.ConfirmedMinutes)
	}
	if alice.IdleMinutes != 2 {
		t.Fatalf("alice idle minutes = %d, want 2", alice.IdleMinutes)
	}
	if alice.DisconnectedMinutes != 1 {
		t.Fatalf("alice disconnected minutes = %d, want 1", alice.DisconnectedMinutes)
	}

	bob := rows[1]
	if bob.User != "bob" {
		t.Fatalf("unexpected second row: %+v", bob)
	}
	if bob.WorkedMinutes != 2 {
		t.Fatalf("bob worked minutes = %d, want 2", bob.WorkedMinutes)
	}
	if bob.UnknownMinutes != 12 {
		t.Fatalf("bob unknown minutes = %d, want 12", bob.UnknownMinutes)
	}
}

func TestSummarizeWithDateAndIntervalFilter(t *testing.T) {
	snapshots, _, err := parser.ParseSnapshotsJSONL(strings.NewReader(sampleSnapshots))
	if err != nil {
		t.Fatal(err)
	}

	rows := Summarize(snapshots, nil, model.Config{
		ActiveIdleThreshold: time.Minute,
		MaxGap:              10 * time.Minute,
		Since:               time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC),
		Until:               time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC),
		DayStartMinutes:     9 * 60,
		DayEndMinutes:       9*60 + 2,
	})

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0].User != "alice" || rows[0].WorkedMinutes != 2 {
		t.Fatalf("unexpected filtered alice row: %+v", rows[0])
	}
	if rows[1].User != "bob" || rows[1].WorkedMinutes != 2 {
		t.Fatalf("unexpected filtered bob row: %+v", rows[1])
	}
}

const sampleSnapshots = `{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":5,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:00:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":10,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:01:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":125,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:03:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"disconnected","idle_seconds":0,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:05:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":20,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:06:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":15,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:08:00Z"}
{"server":"srv-2","user":"bob","session_id":"8","state":"active","idle_seconds":0,"client_ip":"10.0.0.11","captured_at":"2026-04-18T09:00:00Z"}
{"server":"srv-2","user":"bob","session_id":"8","state":"active","idle_seconds":0,"client_ip":"10.0.0.11","captured_at":"2026-04-18T09:02:00Z"}
{"server":"srv-2","user":"bob","session_id":"8","state":"active","idle_seconds":0,"client_ip":"10.0.0.11","captured_at":"2026-04-18T09:14:00Z"}`

const sampleWindows = `{"server":"srv-1","client_ip":"10.0.0.10","started_at":"2026-04-18T09:00:00Z","ended_at":"2026-04-18T09:02:30Z","source":"workstation"}
{"server":"srv-2","user":"bob","started_at":"2026-04-18T09:00:00Z","ended_at":"2026-04-18T09:01:00Z","source":"network"}`
