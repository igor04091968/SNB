package linuxaudit

import (
	"regexp"
	"sort"
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
