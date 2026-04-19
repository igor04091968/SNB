package linuxaudit

import (
	"testing"
	"time"
)

func TestParseLastSessions(t *testing.T) {
	until := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	lines := []string{
		"alice pts/0 10.0.0.5 Tue 2026-04-19 08:00:00 +0000 - Tue 2026-04-19 10:30:00 +0000  (02:30)",
		"bob pts/1 10.0.0.6 Tue 2026-04-19 11:00:00 +0000   still logged in",
	}

	sessions := parseLastSessions(lines, until)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if sessions[0].User != "alice" || sessions[0].Open {
		t.Fatalf("unexpected first session: %+v", sessions[0])
	}
	if sessions[1].User != "bob" || !sessions[1].Open || !sessions[1].Ended.Equal(until) {
		t.Fatalf("unexpected second session: %+v", sessions[1])
	}
}

func TestParseJournalEvidence(t *testing.T) {
	since := time.Date(2026, 4, 19, 8, 0, 0, 0, time.UTC)
	until := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	lines := []string{
		"2026-04-19T09:15:00+00:00 srv sshd[123]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2",
		"2026-04-19T09:20:00+00:00 srv sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status",
	}

	evidence := parseJournalEvidence(lines, since, until)
	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence events, got %d", len(evidence))
	}
	if evidence[0].User != "alice" || evidence[1].User != "alice" {
		t.Fatalf("unexpected evidence users: %+v", evidence)
	}
}

func TestMergeSessionWindows(t *testing.T) {
	windows := []sessionWindow{
		{User: "igor", Started: time.Date(2026, 4, 19, 11, 0, 0, 0, time.UTC), Ended: time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC), Source: "who", Open: true},
		{User: "igor", Started: time.Date(2026, 4, 19, 11, 30, 0, 0, time.UTC), Ended: time.Date(2026, 4, 19, 12, 15, 0, 0, time.UTC), Source: "last", Open: true},
	}

	merged := mergeSessionWindows(windows)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged window, got %d", len(merged))
	}
	if !merged[0].Started.Equal(time.Date(2026, 4, 19, 11, 0, 0, 0, time.UTC)) || !merged[0].Ended.Equal(time.Date(2026, 4, 19, 12, 15, 0, 0, time.UTC)) {
		t.Fatalf("unexpected merged window: %+v", merged[0])
	}
}
