package linuxaudit

import (
	"strconv"
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

func TestParseLoginAccountsFiltersSystemAndNoLoginUsers(t *testing.T) {
	lines := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"sshd:x:101:65534::/run/sshd:/usr/sbin/nologin",
		"igor:x:1000:1000:Igor:/home/igor:/bin/bash",
		"servicebot:x:999:999::/srv/service:/bin/bash",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
	}

	accounts := parseLoginAccounts(lines)
	if len(accounts) != 1 {
		t.Fatalf("expected 1 login account, got %d: %+v", len(accounts), accounts)
	}
	if _, ok := accounts["igor"]; !ok {
		t.Fatalf("expected igor in login accounts: %+v", accounts)
	}
}

func TestFilterEvidenceByAccounts(t *testing.T) {
	accounts := map[string]loginAccount{
		"igor": {User: "igor", UID: 1000, Shell: "/bin/bash"},
	}
	evidence := []evidenceEvent{
		{User: "root", At: time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC), Source: "journalctl"},
		{User: "igor", At: time.Date(2026, 4, 19, 9, 5, 0, 0, time.UTC), Source: "journalctl"},
		{User: "sshd", At: time.Date(2026, 4, 19, 9, 10, 0, 0, time.UTC), Source: "journalctl"},
	}

	filtered := filterEvidenceByAccounts(evidence, accounts)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered evidence event, got %d: %+v", len(filtered), filtered)
	}
	if filtered[0].User != "igor" {
		t.Fatalf("unexpected filtered user: %+v", filtered[0])
	}
}

func TestParseHistoryEventsParsesBashAndZshTimestamps(t *testing.T) {
	since := time.Date(2026, 4, 19, 8, 0, 0, 0, time.UTC)
	until := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	accounts := map[string]loginAccount{
		"igor": {User: "igor", UID: 1000, Home: "/home/igor", Shell: "/bin/bash"},
	}
	bashEpoch := strconv.FormatInt(time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC).Unix(), 10)
	zshEpoch := strconv.FormatInt(time.Date(2026, 4, 19, 9, 30, 0, 0, time.UTC).Unix(), 10)
	lines := []string{
		"__HISTORY__:igor:/home/igor/.bash_history",
		"#" + bashEpoch,
		"ls -la",
		"__HISTORY__:igor:/home/igor/.zsh_history",
		": " + zshEpoch + ":0;git status",
	}

	events := parseHistoryEvents(lines, since, until, accounts)
	if len(events) != 2 {
		t.Fatalf("expected 2 history events, got %d: %+v", len(events), events)
	}
	if events[0].Source != "bash_history" || events[1].Source != "zsh_history" {
		t.Fatalf("unexpected history sources: %+v", events)
	}
	if events[0].Command != "ls -la" || events[0].Category != actionCategoryShell {
		t.Fatalf("unexpected bash event payload: %+v", events[0])
	}
	if events[1].Command != "git status" || events[1].Category != actionCategoryCoding {
		t.Fatalf("unexpected zsh event payload: %+v", events[1])
	}
}

func TestParseTmuxEventsParsesCreatedAndActivityEpochs(t *testing.T) {
	since := time.Date(2026, 4, 19, 8, 0, 0, 0, time.UTC)
	until := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	accounts := map[string]loginAccount{
		"igor": {User: "igor", UID: 1000, Home: "/home/igor", Shell: "/bin/bash"},
	}
	created := strconv.FormatInt(time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC).Unix(), 10)
	activity := strconv.FormatInt(time.Date(2026, 4, 19, 9, 12, 0, 0, time.UTC).Unix(), 10)
	lines := []string{
		"__TMUX__:igor:/tmp/tmux-1000/default",
		created + "|" + activity + "|1|work",
	}

	events := parseTmuxEvents(lines, since, until, accounts)
	if len(events) != 2 {
		t.Fatalf("expected 2 tmux events, got %d: %+v", len(events), events)
	}
	if events[0].Source != "tmux" || events[1].Source != "tmux" {
		t.Fatalf("unexpected tmux sources: %+v", events)
	}
	if !events[0].At.Equal(time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)) || !events[1].At.Equal(time.Date(2026, 4, 19, 9, 12, 0, 0, time.UTC)) {
		t.Fatalf("unexpected tmux timestamps: %+v", events)
	}
	if events[0].Category != actionCategoryShell || events[0].Command == "" {
		t.Fatalf("unexpected tmux payload: %+v", events[0])
	}
}

func TestClassifyCommandDistinguishesCodingAndConfig(t *testing.T) {
	category, paths := classifyCommand("vim /etc/nginx/nginx.conf")
	if category != actionCategoryConfig {
		t.Fatalf("expected config category, got %q", category)
	}
	if len(paths) != 1 || paths[0] != "/etc/nginx/nginx.conf" {
		t.Fatalf("unexpected config paths: %+v", paths)
	}

	category, paths = classifyCommand("go test ./internal/linuxaudit")
	if category != actionCategoryCoding {
		t.Fatalf("expected coding category, got %q", category)
	}
	if len(paths) != 1 || paths[0] != "./internal/linuxaudit" {
		t.Fatalf("unexpected coding paths: %+v", paths)
	}
}

func TestClassifyCommandRecognizesAbsoluteBinaryPaths(t *testing.T) {
	category, _ := classifyCommand("/usr/bin/systemctl restart nginx")
	if category != actionCategoryConfig {
		t.Fatalf("expected config category, got %q", category)
	}

	category, _ = classifyCommand("/usr/bin/git status")
	if category != actionCategoryCoding {
		t.Fatalf("expected coding category, got %q", category)
	}
}

func TestParseSudoCommandEventsExtractsCommandsFromJournalAndAuthlog(t *testing.T) {
	// auth.log timestamps are in server local time; cfg.Since/Until are stored in UTC but derived from time.Local.
	sinceLocal := time.Date(2026, 4, 19, 8, 0, 0, 0, time.Local)
	untilLocal := time.Date(2026, 4, 19, 12, 0, 0, 0, time.Local)
	since := sinceLocal.UTC()
	until := untilLocal.UTC()
	accounts := map[string]loginAccount{
		"alice": {User: "alice", UID: 1000, Home: "/home/alice", Shell: "/bin/bash"},
	}
	journal := []string{
		"2026-04-19T09:20:00+03:00 srv sudo[123]:  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
	}
	authlog := []string{
		"Apr 19 09:30:00 srv sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/git status",
	}

	events := parseSudoCommandEvents(journal, authlog, since, until, accounts)
	if len(events) != 2 {
		t.Fatalf("expected 2 sudo events, got %d: %+v", len(events), events)
	}
	if events[0].User != "alice" || events[1].User != "alice" {
		t.Fatalf("unexpected sudo users: %+v", events)
	}
	if events[0].Source != "sudo_journal" || events[1].Source != "sudo_authlog" {
		t.Fatalf("unexpected sudo sources: %+v", events)
	}
	if events[0].Category != actionCategoryConfig {
		t.Fatalf("unexpected sudo journal category: %+v", events[0])
	}
	if events[1].Category != actionCategoryCoding {
		t.Fatalf("unexpected sudo authlog category: %+v", events[1])
	}
}
