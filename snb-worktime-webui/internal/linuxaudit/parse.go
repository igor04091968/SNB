package linuxaudit

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	lastTimePattern    = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+\-]\d{4}`)
	journalTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\+\d{2}:\d{2}|Z)`)
	authTimePattern    = regexp.MustCompile(`^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}`)
	userPatterns       = []*regexp.Regexp{
		regexp.MustCompile(`Accepted \S+ for ([A-Za-z0-9._-]+)`),
		regexp.MustCompile(`session opened for user ([A-Za-z0-9._-]+)`),
		regexp.MustCompile(`session closed for user ([A-Za-z0-9._-]+)`),
		regexp.MustCompile(`sudo: +([A-Za-z0-9._-]+) *:`),
		regexp.MustCompile(`user=([A-Za-z0-9._-]+)`),
		regexp.MustCompile(`for ([A-Za-z0-9._-]+) from`),
		regexp.MustCompile(`for ([A-Za-z0-9._-]+)$`),
	}
)

func splitSections(raw string) sectionedOutput {
	var output sectionedOutput
	var current *[]string

	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "__SECTION__:") {
			switch strings.TrimPrefix(line, "__SECTION__:") {
			case "HOSTNAME":
				current = nil
			case "PASSWD":
				current = &output.Passwd
			case "LAST":
				current = &output.Last
			case "WHO":
				current = &output.Who
			case "JOURNAL":
				current = &output.Journal
			case "AUTHLOG":
				current = &output.AuthLog
			}
			continue
		}

		if output.HostName == "" && current == nil && strings.TrimSpace(line) != "" {
			output.HostName = strings.TrimSpace(line)
			continue
		}
		if current != nil {
			*current = append(*current, line)
		}
	}
	return output
}

type loginAccount struct {
	User  string
	UID   int
	Home  string
	Shell string
}

func parseLoginAccounts(lines []string) map[string]loginAccount {
	accounts := map[string]loginAccount{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		user := strings.TrimSpace(fields[0])
		uid, err := strconv.Atoi(strings.TrimSpace(fields[2]))
		if err != nil {
			continue
		}
		home := strings.TrimSpace(fields[5])
		shell := strings.TrimSpace(fields[6])
		if !isInteractiveShell(shell) || isSystemUID(uid) || isSystemHome(home) {
			continue
		}
		accounts[user] = loginAccount{
			User:  user,
			UID:   uid,
			Home:  home,
			Shell: shell,
		}
	}
	return accounts
}

func isInteractiveShell(shell string) bool {
	shell = strings.TrimSpace(shell)
	if shell == "" {
		return false
	}
	blocked := []string{
		"/usr/sbin/nologin",
		"/usr/bin/nologin",
		"/sbin/nologin",
		"/bin/nologin",
		"/usr/bin/false",
		"/bin/false",
		"nologin",
		"false",
		"sync",
		"shutdown",
		"halt",
	}
	for _, item := range blocked {
		if shell == item {
			return false
		}
	}
	return true
}

func isSystemUID(uid int) bool {
	return uid < 1000
}

func isSystemHome(home string) bool {
	home = strings.TrimSpace(home)
	if home == "" {
		return true
	}
	blocked := []string{"/nonexistent", "/var/empty", "/var/lib/nobody"}
	for _, item := range blocked {
		if home == item {
			return true
		}
	}
	return false
}

func filterSessionsByAccounts(sessions []sessionWindow, accounts map[string]loginAccount) []sessionWindow {
	if len(accounts) == 0 {
		return nil
	}
	var filtered []sessionWindow
	for _, session := range sessions {
		user := normalizeUser(session.User)
		if _, ok := accounts[user]; !ok {
			continue
		}
		session.User = user
		filtered = append(filtered, session)
	}
	return filtered
}

func filterEvidenceByAccounts(evidence []evidenceEvent, accounts map[string]loginAccount) []evidenceEvent {
	if len(accounts) == 0 {
		return nil
	}
	var filtered []evidenceEvent
	for _, item := range evidence {
		user := normalizeUser(item.User)
		if _, ok := accounts[user]; !ok {
			continue
		}
		item.User = user
		filtered = append(filtered, item)
	}
	return filtered
}

func detectAccountWarnings(accounts map[string]loginAccount) []string {
	if len(accounts) == 0 {
		return []string{"no non-system shell accounts discovered via passwd"}
	}
	list := make([]string, 0, len(accounts))
	for user := range accounts {
		list = append(list, user)
	}
	sort.Strings(list)
	return []string{fmt.Sprintf("linux audit limited to shell users: %s", strings.Join(list, ", "))}
}

func parseLastSessions(lines []string, until time.Time) []sessionWindow {
	var sessions []sessionWindow
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "wtmp begins") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		user := fields[0]
		if user == "reboot" || user == "shutdown" || user == "runlevel" {
			continue
		}

		matches := lastTimePattern.FindAllString(line, -1)
		if len(matches) == 0 {
			continue
		}
		started, err := time.Parse("2006-01-02 15:04:05 -0700", matches[0])
		if err != nil {
			continue
		}
		ended := until
		open := strings.Contains(line, "still logged in")
		if len(matches) > 1 {
			parsedEnd, err := time.Parse("2006-01-02 15:04:05 -0700", matches[1])
			if err == nil {
				ended = parsedEnd
				open = false
			}
		}
		sessions = append(sessions, sessionWindow{
			User:    user,
			Started: started.UTC(),
			Ended:   ended.UTC(),
			Source:  "last",
			Open:    open,
		})
	}
	return sessions
}

func parseWhoSessions(lines []string, until time.Time) []sessionWindow {
	var sessions []sessionWindow
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		started, err := time.ParseInLocation("2006-01-02 15:04", fields[2]+" "+fields[3], time.Local)
		if err != nil {
			continue
		}
		sessions = append(sessions, sessionWindow{
			User:    fields[0],
			Started: started.UTC(),
			Ended:   until.UTC(),
			Source:  "who",
			Open:    true,
		})
	}
	return sessions
}

func parseJournalEvidence(lines []string, since time.Time, until time.Time) []evidenceEvent {
	return parseEvidence(lines, since, until, "journalctl", func(line string) (time.Time, bool) {
		match := journalTimePattern.FindString(line)
		if match == "" {
			return time.Time{}, false
		}
		parsed, err := time.Parse(time.RFC3339, match)
		if err != nil {
			return time.Time{}, false
		}
		return parsed.UTC(), true
	})
}

func parseAuthEvidence(lines []string, since time.Time, until time.Time) []evidenceEvent {
	return parseEvidence(lines, since, until, "authlog", func(line string) (time.Time, bool) {
		match := authTimePattern.FindString(line)
		if match == "" {
			return time.Time{}, false
		}
		parsed, err := time.ParseInLocation("Jan 2 15:04:05", match, time.Local)
		if err != nil {
			return time.Time{}, false
		}
		parsed = parsed.AddDate(since.Year()-parsed.Year(), 0, 0)
		return parsed.UTC(), true
	})
}

func parseEvidence(lines []string, since time.Time, until time.Time, source string, parseTime func(string) (time.Time, bool)) []evidenceEvent {
	var evidence []evidenceEvent
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "FILE:") {
			continue
		}
		timestamp, ok := parseTime(line)
		if !ok {
			continue
		}
		if timestamp.Before(since) || timestamp.After(until) {
			continue
		}
		user := extractUser(line)
		if user == "" {
			continue
		}
		evidence = append(evidence, evidenceEvent{User: user, At: timestamp, Source: source})
	}
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].At.Before(evidence[j].At)
	})
	return evidence
}

func extractUser(line string) string {
	for _, pattern := range userPatterns {
		match := pattern.FindStringSubmatch(line)
		if len(match) > 1 {
			return match[1]
		}
	}
	return ""
}
