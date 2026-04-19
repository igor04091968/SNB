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
	bashEpochPattern   = regexp.MustCompile(`^#(\d{9,})$`)
	zshHistoryPattern  = regexp.MustCompile(`^: (\d{9,}):\d+;(.*)$`)
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
			case "HISTORY":
				current = &output.History
			case "TMUX":
				current = &output.Tmux
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

func parseHistoryEvents(lines []string, since time.Time, until time.Time, accounts map[string]loginAccount) []commandEvent {
	if len(lines) == 0 || len(accounts) == 0 {
		return nil
	}

	var (
		events       []commandEvent
		currentUser  string
		currentFile  string
		pendingEpoch int64
	)

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "__HISTORY__:") {
			currentUser, currentFile = parseHistoryHeader(strings.TrimPrefix(line, "__HISTORY__:"))
			pendingEpoch = 0
			continue
		}
		if currentUser == "" || currentFile == "" {
			continue
		}
		user := normalizeUser(currentUser)
		if _, ok := accounts[user]; !ok {
			continue
		}
		for _, event := range parseHistoryLine(user, currentFile, line, &pendingEpoch) {
			if event.At.Before(since) || event.At.After(until) {
				continue
			}
			events = append(events, event)
		}
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			if events[i].User == events[j].User {
				return events[i].Source < events[j].Source
			}
			return events[i].User < events[j].User
		}
		return events[i].At.Before(events[j].At)
	})
	return events
}

func parseTmuxEvents(lines []string, since time.Time, until time.Time, accounts map[string]loginAccount) []commandEvent {
	if len(lines) == 0 || len(accounts) == 0 {
		return nil
	}

	var (
		events      []commandEvent
		currentUser string
	)

	for _, raw := range lines {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(line, "__TMUX__:") {
			currentUser = parseTmuxHeader(strings.TrimPrefix(line, "__TMUX__:"))
			continue
		}
		if currentUser == "" {
			continue
		}
		user := normalizeUser(currentUser)
		if _, ok := accounts[user]; !ok {
			continue
		}
		for _, event := range parseTmuxLine(user, line) {
			if event.At.Before(since) || event.At.After(until) {
				continue
			}
			events = append(events, event)
		}
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			if events[i].User == events[j].User {
				return events[i].Source < events[j].Source
			}
			return events[i].User < events[j].User
		}
		return events[i].At.Before(events[j].At)
	})
	return events
}

func parseHistoryHeader(value string) (string, string) {
	user, path, found := strings.Cut(value, ":")
	if !found {
		return "", ""
	}
	return strings.TrimSpace(user), strings.TrimSpace(path)
}

func parseHistoryLine(user string, file string, line string, pendingEpoch *int64) []commandEvent {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	if match := bashEpochPattern.FindStringSubmatch(line); len(match) > 1 {
		epoch, err := strconv.ParseInt(match[1], 10, 64)
		if err == nil {
			*pendingEpoch = epoch
		}
		return nil
	}

	if match := zshHistoryPattern.FindStringSubmatch(line); len(match) > 1 {
		epoch, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return nil
		}
		command := ""
		if len(match) > 2 {
			command = strings.TrimSpace(match[2])
		}
		category, paths := classifyCommand(command)
		return []commandEvent{{
			User:     user,
			At:       time.Unix(epoch, 0).UTC(),
			Source:   historySource(file),
			Command:  command,
			Category: category,
			Paths:    paths,
		}}
	}

	if *pendingEpoch == 0 {
		return nil
	}

	category, paths := classifyCommand(line)
	event := commandEvent{
		User:     user,
		At:       time.Unix(*pendingEpoch, 0).UTC(),
		Source:   historySource(file),
		Command:  line,
		Category: category,
		Paths:    paths,
	}
	*pendingEpoch = 0
	return []commandEvent{event}
}

func historySource(path string) string {
	switch {
	case strings.HasSuffix(path, ".zsh_history"):
		return "zsh_history"
	default:
		return "bash_history"
	}
}

func parseTmuxHeader(value string) string {
	user, _, _ := strings.Cut(value, ":")
	return strings.TrimSpace(user)
}

func parseTmuxLine(user string, line string) []commandEvent {
	if line == "" {
		return nil
	}

	fields := strings.SplitN(line, "|", 4)
	if len(fields) < 2 {
		return nil
	}

	seen := map[int64]struct{}{}
	var events []commandEvent
	sessionName := ""
	if len(fields) > 3 {
		sessionName = strings.TrimSpace(fields[3])
	}
	summary := "tmux session activity"
	if sessionName != "" {
		summary = "tmux session: " + sessionName
	}
	for _, raw := range fields[:2] {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		epoch, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || epoch <= 0 {
			continue
		}
		if _, ok := seen[epoch]; ok {
			continue
		}
		seen[epoch] = struct{}{}
		events = append(events, commandEvent{
			User:     user,
			At:       time.Unix(epoch, 0).UTC(),
			Source:   "tmux",
			Command:  summary,
			Category: actionCategoryShell,
		})
	}
	return events
}

const (
	actionCategoryShell  = "shell"
	actionCategoryCoding = "coding"
	actionCategoryConfig = "config"
)

func classifyCommand(command string) (string, []string) {
	command = strings.TrimSpace(command)
	if command == "" {
		return actionCategoryShell, nil
	}

	paths := extractCommandPaths(command)
	lower := strings.ToLower(command)

	if isConfigCommand(lower, paths) {
		return actionCategoryConfig, paths
	}
	if isCodingCommand(lower, paths) {
		return actionCategoryCoding, paths
	}
	return actionCategoryShell, paths
}

func isCodingCommand(lower string, paths []string) bool {
	codingPrefixes := []string{
		"git ", "go ", "npm ", "yarn ", "pnpm ", "make ", "cmake ", "cargo ",
		"pytest", "python ", "python3 ", "pip ", "pip3 ", "node ", "npx ",
		"composer ", "bundle ", "gradle ", "mvn ", "javac ", "gcc ", "g++ ",
		"clang ", "clang++ ", "rustc ", "phpunit", "rails ", "mix ", "deno ",
	}
	for _, prefix := range codingPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	editorPrefixes := []string{"vim ", "vi ", "nvim ", "nano ", "emacs ", "code ", "sed -i", "tee ", "cat >"}
	for _, prefix := range editorPrefixes {
		if strings.HasPrefix(lower, prefix) && hasCodePath(paths) {
			return true
		}
	}

	return hasCodePath(paths)
}

func isConfigCommand(lower string, paths []string) bool {
	configPrefixes := []string{
		"systemctl ", "service ", "nginx ", "apachectl ", "httpd ", "a2en", "a2dis",
		"asterisk ", "fwconsole ", "supervisorctl ", "netplan ", "ufw ", "iptables ",
		"firewall-cmd ", "crontab ", "visudo", "sudoedit ", "sysctl ",
	}
	for _, prefix := range configPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	editorPrefixes := []string{"vim ", "vi ", "nvim ", "nano ", "emacs ", "sed -i", "tee ", "cat >"}
	for _, prefix := range editorPrefixes {
		if strings.HasPrefix(lower, prefix) && hasConfigPath(paths) {
			return true
		}
	}

	return hasConfigPath(paths)
}

func extractCommandPaths(command string) []string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	var paths []string
	for _, field := range fields {
		token := normalizeCommandToken(field)
		if token == "" || strings.HasPrefix(token, "-") {
			continue
		}
		if !looksLikePath(token) {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		paths = append(paths, token)
		if len(paths) >= 8 {
			break
		}
	}
	sort.Strings(paths)
	return paths
}

func normalizeCommandToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\"'")
	token = strings.TrimRight(token, ",;:()[]{}")
	token = strings.TrimLeft(token, "><")
	return token
}

func looksLikePath(token string) bool {
	if token == "" {
		return false
	}
	if strings.HasPrefix(token, "/") || strings.HasPrefix(token, "~/") || strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") {
		return true
	}
	if strings.Contains(token, "/") {
		return true
	}
	return strings.Contains(token, ".")
}

func hasCodePath(paths []string) bool {
	for _, path := range paths {
		lower := strings.ToLower(path)
		switch {
		case strings.HasSuffix(lower, ".go"),
			strings.HasSuffix(lower, ".js"),
			strings.HasSuffix(lower, ".ts"),
			strings.HasSuffix(lower, ".tsx"),
			strings.HasSuffix(lower, ".jsx"),
			strings.HasSuffix(lower, ".py"),
			strings.HasSuffix(lower, ".rb"),
			strings.HasSuffix(lower, ".php"),
			strings.HasSuffix(lower, ".java"),
			strings.HasSuffix(lower, ".c"),
			strings.HasSuffix(lower, ".cc"),
			strings.HasSuffix(lower, ".cpp"),
			strings.HasSuffix(lower, ".h"),
			strings.HasSuffix(lower, ".hpp"),
			strings.HasSuffix(lower, ".rs"),
			strings.HasSuffix(lower, ".sh"),
			strings.HasSuffix(lower, ".sql"),
			strings.HasSuffix(lower, ".html"),
			strings.HasSuffix(lower, ".css"),
			strings.HasSuffix(lower, ".scss"),
			strings.HasSuffix(lower, ".tf"),
			strings.HasSuffix(lower, ".proto"),
			strings.HasSuffix(lower, "dockerfile"),
			strings.HasSuffix(lower, "makefile"):
			return true
		}
	}
	return false
}

func hasConfigPath(paths []string) bool {
	for _, path := range paths {
		lower := strings.ToLower(path)
		switch {
		case strings.HasPrefix(lower, "/etc/"),
			strings.Contains(lower, "/conf/"),
			strings.Contains(lower, "/config/"),
			strings.HasSuffix(lower, ".conf"),
			strings.HasSuffix(lower, ".cfg"),
			strings.HasSuffix(lower, ".cnf"),
			strings.HasSuffix(lower, ".ini"),
			strings.HasSuffix(lower, ".yaml"),
			strings.HasSuffix(lower, ".yml"),
			strings.HasSuffix(lower, ".json"),
			strings.HasSuffix(lower, ".toml"),
			strings.HasSuffix(lower, ".env"),
			strings.HasSuffix(lower, ".service"),
			strings.HasSuffix(lower, ".socket"),
			strings.HasSuffix(lower, ".timer"),
			strings.HasSuffix(lower, ".target"),
			strings.HasSuffix(lower, ".properties"),
			strings.HasSuffix(lower, ".xml"),
			strings.HasSuffix(lower, "nginx.conf"),
			strings.HasSuffix(lower, "httpd.conf"),
			strings.HasSuffix(lower, "pjsip.conf"),
			strings.HasSuffix(lower, "extensions.conf"):
			return true
		}
	}
	return false
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
