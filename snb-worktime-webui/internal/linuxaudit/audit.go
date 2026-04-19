package linuxaudit

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"snb-worktime-webui/internal/model"
	"snb-worktime-webui/internal/timewindow"
)

const (
	commandActivityGap = 15 * time.Minute
	commandPointWindow = time.Minute
)

type sessionWindow struct {
	User    string
	Started time.Time
	Ended   time.Time
	Source  string
	Open    bool
}

type evidenceEvent struct {
	User   string
	At     time.Time
	Source string
}

type commandEvent struct {
	User     string
	At       time.Time
	Source   string
	Command  string
	Category string
	Paths    []string
}

type sectionedOutput struct {
	HostName string
	Passwd   []string
	Last     []string
	Who      []string
	Journal  []string
	AuthLog  []string
	History  []string
	Tmux     []string
}

func Audit(servers []model.LinuxServer, cfg model.Config) model.LinuxAuditResponse {
	if cfg.Until.IsZero() {
		cfg.Until = time.Now().UTC()
	}
	if cfg.Since.IsZero() {
		cfg.Since = cfg.Until.Add(-24 * time.Hour)
	}
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}

	response := model.LinuxAuditResponse{
		Rows:           []model.LinuxAuditRow{},
		Warnings:       []string{},
		ScannedServers: len(servers),
	}

	for _, server := range servers {
		rows, warnings, err := auditServer(server, cfg)
		if err != nil {
			response.Warnings = append(response.Warnings, fmt.Sprintf("%s: %v", server.NameOrHost(), err))
			continue
		}
		response.SuccessfulHosts++
		response.Rows = append(response.Rows, rows...)
		response.Warnings = append(response.Warnings, warnings...)
	}

	sort.Slice(response.Rows, func(i, j int) bool {
		if response.Rows[i].SessionMinutes == response.Rows[j].SessionMinutes {
			if response.Rows[i].CommandMinutes == response.Rows[j].CommandMinutes {
				if response.Rows[i].Server == response.Rows[j].Server {
					return response.Rows[i].User < response.Rows[j].User
				}
				return response.Rows[i].Server < response.Rows[j].Server
			}
			return response.Rows[i].CommandMinutes > response.Rows[j].CommandMinutes
		}
		return response.Rows[i].SessionMinutes > response.Rows[j].SessionMinutes
	})

	return response
}

func auditServer(server model.LinuxServer, cfg model.Config) ([]model.LinuxAuditRow, []string, error) {
	output, err := runRemoteAudit(server, cfg.Since, cfg.Until)
	if err != nil {
		return nil, nil, err
	}

	sections := splitSections(output)
	loginAccounts := parseLoginAccounts(sections.Passwd)
	sessions := append(parseLastSessions(sections.Last, cfg.Until), parseWhoSessions(sections.Who, cfg.Until)...)
	evidence := append(parseJournalEvidence(sections.Journal, cfg.Since, cfg.Until), parseAuthEvidence(sections.AuthLog, cfg.Since, cfg.Until)...)
	commands := append(
		parseHistoryEvents(sections.History, cfg.Since, cfg.Until, loginAccounts),
		parseTmuxEvents(sections.Tmux, cfg.Since, cfg.Until, loginAccounts)...,
	)
	sessions = filterSessionsByAccounts(sessions, loginAccounts)
	evidence = filterEvidenceByAccounts(evidence, loginAccounts)

	byUser := map[string]*aggregate{}
	sessionCoverage := map[string][]sessionWindow{}
	commandCoverage := map[string][]commandEvent{}
	for _, session := range sessions {
		user := normalizeUser(session.User)
		if user == "" {
			continue
		}
		agg := ensureAggregate(byUser, user)
		agg.sessionCount++
		agg.sources[session.Source] = struct{}{}
		sessionCoverage[user] = append(sessionCoverage[user], session)
	}
	for _, item := range commands {
		user := normalizeUser(item.User)
		if user == "" {
			continue
		}
		commandCoverage[user] = append(commandCoverage[user], item)
	}

	mergedSessionCoverage := map[string][]sessionWindow{}
	for user, windows := range sessionCoverage {
		agg := ensureAggregate(byUser, user)
		merged := mergeSessionWindows(windows)
		mergedSessionCoverage[user] = merged
		for _, window := range merged {
			segments := timewindow.Segments(window.Started, window.Ended, cfg.Since, cfg.Until, cfg.DayStartMinutes, cfg.DayEndMinutes, cfg.Location)
			for _, segment := range segments {
				minutes := int64(segment.End.Sub(segment.Start) / time.Minute)
				if minutes <= 0 {
					continue
				}
				agg.sessionMinutes += minutes
				if window.Open {
					agg.openMinutes += minutes
				}
				updateSeen(agg, segment.Start)
				updateSeen(agg, segment.End)
				agg.intervals = append(agg.intervals, model.LinuxAuditInterval{
					StartedAt:       formatTime(segment.Start),
					EndedAt:         formatTime(segment.End),
					DurationMinutes: minutes,
					DurationHuman:   humanMinutes(minutes),
					Open:            window.Open,
					SourceSummary:   strings.ReplaceAll(window.Source, ",", ", "),
				})
			}
		}
		agg.openSessions = countOpenSessions(merged)
	}

	for user, events := range commandCoverage {
		agg := ensureAggregate(byUser, user)
		confirmedEvents := filterEventsWithinSessions(events, mergedSessionCoverage[user])
		agg.commandCount = len(confirmedEvents)
		for _, item := range confirmedEvents {
			agg.sources[item.Source] = struct{}{}
			updateSeen(agg, item.At)
			agg.actions = append(agg.actions, model.LinuxAuditAction{
				At:       formatTime(item.At),
				Category: item.Category,
				Summary:  summarizeCommand(item.Command),
				Source:   item.Source,
				Paths:    append([]string(nil), item.Paths...),
			})
		}
		agg.commandMinutes, agg.commandWindows = buildTimedIntervals(confirmedEvents, cfg)

		codingEvents := filterEventsByCategory(confirmedEvents, actionCategoryCoding)
		configEvents := filterEventsByCategory(confirmedEvents, actionCategoryConfig)

		agg.codingCount = len(codingEvents)
		agg.configCount = len(configEvents)
		agg.codingMinutes, agg.codingWindows = buildTimedIntervals(codingEvents, cfg)
		agg.configMinutes, agg.configWindows = buildTimedIntervals(configEvents, cfg)
	}

	for _, item := range evidence {
		user := normalizeUser(item.User)
		if user == "" {
			continue
		}
		agg := ensureAggregate(byUser, user)
		agg.evidenceCount++
		agg.sources[item.Source] = struct{}{}
		updateSeen(agg, item.At)
	}

	var rows []model.LinuxAuditRow
	for user, agg := range byUser {
		rows = append(rows, model.LinuxAuditRow{
			Server:         server.DisplayName(sections.HostName),
			User:           user,
			SessionMinutes: agg.sessionMinutes,
			SessionHuman:   humanMinutes(agg.sessionMinutes),
			CommandMinutes: agg.commandMinutes,
			CommandHuman:   humanMinutes(agg.commandMinutes),
			CodingMinutes:  agg.codingMinutes,
			CodingHuman:    humanMinutes(agg.codingMinutes),
			ConfigMinutes:  agg.configMinutes,
			ConfigHuman:    humanMinutes(agg.configMinutes),
			OpenMinutes:    agg.openMinutes,
			OpenHuman:      humanMinutes(agg.openMinutes),
			SessionCount:   agg.sessionCount,
			CommandCount:   agg.commandCount,
			CodingCount:    agg.codingCount,
			ConfigCount:    agg.configCount,
			OpenSessions:   agg.openSessions,
			EvidenceCount:  agg.evidenceCount,
			SourceSummary:  joinSources(agg.sources),
			FirstSeen:      formatTime(agg.firstSeen),
			LastSeen:       formatTime(agg.lastSeen),
			HasSessions:    len(agg.intervals) > 0,
			Intervals:      agg.intervals,
			CommandWindows: agg.commandWindows,
			CodingWindows:  agg.codingWindows,
			ConfigWindows:  agg.configWindows,
			Actions:        agg.actions,
		})
	}

	return rows, append(detectWarnings(sections), detectAccountWarnings(loginAccounts)...), nil
}

func runRemoteAudit(server model.LinuxServer, since time.Time, until time.Time) (string, error) {
	config, err := sshConfig(server)
	if err != nil {
		return "", err
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(server.Host, fmt.Sprintf("%d", server.PortOrDefault())), config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	command := buildRemoteCommand(since, until)
	if err := session.Run(command); err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", err
	}

	return stdout.String(), nil
}

func sshConfig(server model.LinuxServer) (*ssh.ClientConfig, error) {
	methods := append([]ssh.AuthMethod{}, defaultAuthMethods()...)
	if strings.TrimSpace(server.PrivateKeyPEM) != "" {
		signer, err := parseSigner(server.PrivateKeyPEM, server.PrivateKeyPassphrase)
		if err != nil {
			return nil, err
		}
		methods = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, methods...)
	}
	if strings.TrimSpace(server.Password) != "" {
		methods = append(methods, ssh.Password(server.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth configured for %s", server.NameOrHost())
	}

	hostKeyCallback, err := hostKeyCallback(defaultKnownHostsPath())
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            server.Username,
		Auth:            methods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         12 * time.Second,
	}, nil
}

func defaultAuthMethods() []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	if agentMethod := sshAgentAuthMethod(); agentMethod != nil {
		methods = append(methods, agentMethod)
	}
	if keyMethod := localKeyAuthMethod(); keyMethod != nil {
		methods = append(methods, keyMethod)
	}

	return methods
}

func sshAgentAuthMethod() ssh.AuthMethod {
	socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socket == "" {
		return nil
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers)
}

func localKeyAuthMethod() ssh.AuthMethod {
	signers := localPrivateKeySigners()
	if len(signers) == 0 {
		return nil
	}
	return ssh.PublicKeys(signers...)
}

func localPrivateKeySigners() []ssh.Signer {
	homeDir, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return nil
	}

	candidates := []string{
		"id_ed25519",
		"id_ecdsa",
		"id_rsa",
		"identity",
	}
	var signers []ssh.Signer
	for _, name := range candidates {
		path := filepath.Join(homeDir, ".ssh", name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}
	return signers
}

func defaultKnownHostsPath() string {
	if value := strings.TrimSpace(os.Getenv("WORKTIME_KNOWN_HOSTS")); value != "" {
		return value
	}
	return filepath.Join("state", "linux_known_hosts")
}

func hostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	_ = file.Close()

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		checkKnownHost, err := knownhosts.New(path)
		if err != nil {
			return err
		}
		err = checkKnownHost(hostname, remote, key)
		if err == nil {
			return nil
		}

		keyErr, ok := err.(*knownhosts.KeyError)
		if !ok || len(keyErr.Want) != 0 {
			return err
		}

		return appendKnownHost(path, hostname, key)
	}, nil
}

func appendKnownHost(path string, hostname string, key ssh.PublicKey) error {
	normalized := knownhosts.Normalize(hostname)
	line := knownhosts.Line([]string{normalized}, key) + "\n"
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(line); err != nil {
		return err
	}
	return nil
}

func parseSigner(pemText string, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(pemText), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(pemText))
}

func ensureAggregate(byUser map[string]*aggregate, user string) *aggregate {
	agg := byUser[user]
	if agg == nil {
		agg = &aggregate{sources: map[string]struct{}{}}
		byUser[user] = agg
	}
	return agg
}

type aggregate struct {
	sessionMinutes int64
	commandMinutes int64
	codingMinutes  int64
	configMinutes  int64
	openMinutes    int64
	sessionCount   int
	commandCount   int
	codingCount    int
	configCount    int
	openSessions   int
	evidenceCount  int
	firstSeen      time.Time
	lastSeen       time.Time
	sources        map[string]struct{}
	intervals      []model.LinuxAuditInterval
	commandWindows []model.LinuxAuditInterval
	codingWindows  []model.LinuxAuditInterval
	configWindows  []model.LinuxAuditInterval
	actions        []model.LinuxAuditAction
}

func updateSeen(agg *aggregate, moment time.Time) {
	if moment.IsZero() {
		return
	}
	if agg.firstSeen.IsZero() || moment.Before(agg.firstSeen) {
		agg.firstSeen = moment
	}
	if agg.lastSeen.IsZero() || moment.After(agg.lastSeen) {
		agg.lastSeen = moment
	}
}

func humanMinutes(minutes int64) string {
	if minutes <= 0 {
		return "0m"
	}
	hours := minutes / 60
	remainder := minutes % 60
	if hours == 0 {
		return fmt.Sprintf("%dm", remainder)
	}
	if remainder == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh %dm", hours, remainder)
}

func mergeSessionWindows(windows []sessionWindow) []sessionWindow {
	if len(windows) == 0 {
		return nil
	}
	sorted := append([]sessionWindow(nil), windows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Started.Equal(sorted[j].Started) {
			return sorted[i].Ended.Before(sorted[j].Ended)
		}
		return sorted[i].Started.Before(sorted[j].Started)
	})

	merged := []sessionWindow{sorted[0]}
	for _, current := range sorted[1:] {
		last := &merged[len(merged)-1]
		if !current.Started.After(last.Ended) {
			if current.Ended.After(last.Ended) {
				last.Ended = current.Ended
			}
			last.Open = last.Open || current.Open
			last.Source = joinWindowSources(last.Source, current.Source)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func buildCommandWindows(events []commandEvent) []sessionWindow {
	if len(events) == 0 {
		return nil
	}

	sorted := append([]commandEvent(nil), events...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].At.Equal(sorted[j].At) {
			return sorted[i].Source < sorted[j].Source
		}
		return sorted[i].At.Before(sorted[j].At)
	})

	current := sessionWindow{
		User:    sorted[0].User,
		Started: sorted[0].At,
		Ended:   sorted[0].At.Add(commandPointWindow),
		Source:  sorted[0].Source,
	}
	var windows []sessionWindow
	for _, item := range sorted[1:] {
		eventEnd := item.At.Add(commandPointWindow)
		if item.At.Sub(current.Ended) <= commandActivityGap {
			if eventEnd.After(current.Ended) {
				current.Ended = eventEnd
			}
			current.Source = joinWindowSources(current.Source, item.Source)
			continue
		}
		windows = append(windows, current)
		current = sessionWindow{
			User:    item.User,
			Started: item.At,
			Ended:   eventEnd,
			Source:  item.Source,
		}
	}
	windows = append(windows, current)
	return windows
}

func filterEventsWithinSessions(events []commandEvent, bounds []sessionWindow) []commandEvent {
	if len(events) == 0 || len(bounds) == 0 {
		return nil
	}
	var filtered []commandEvent
	for _, item := range events {
		for _, bound := range bounds {
			if item.At.Before(bound.Started) || item.At.After(bound.Ended) {
				continue
			}
			filtered = append(filtered, item)
			break
		}
	}
	return filtered
}

func filterEventsByCategory(events []commandEvent, category string) []commandEvent {
	if len(events) == 0 {
		return nil
	}
	var filtered []commandEvent
	for _, item := range events {
		if item.Category != category {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func buildTimedIntervals(events []commandEvent, cfg model.Config) (int64, []model.LinuxAuditInterval) {
	windows := buildCommandWindows(events)
	if len(windows) == 0 {
		return 0, nil
	}
	var totalMinutes int64
	var intervals []model.LinuxAuditInterval
	for _, window := range windows {
		segments := timewindow.Segments(window.Started, window.Ended, cfg.Since, cfg.Until, cfg.DayStartMinutes, cfg.DayEndMinutes, cfg.Location)
		for _, segment := range segments {
			minutes := int64(segment.End.Sub(segment.Start) / time.Minute)
			if minutes <= 0 {
				continue
			}
			totalMinutes += minutes
			intervals = append(intervals, model.LinuxAuditInterval{
				StartedAt:       formatTime(segment.Start),
				EndedAt:         formatTime(segment.End),
				DurationMinutes: minutes,
				DurationHuman:   humanMinutes(minutes),
				Open:            false,
				SourceSummary:   strings.ReplaceAll(window.Source, ",", ", "),
			})
		}
	}
	return totalMinutes, intervals
}

func intersectSessionWindows(windows []sessionWindow, bounds []sessionWindow) []sessionWindow {
	if len(windows) == 0 || len(bounds) == 0 {
		return nil
	}

	var intersections []sessionWindow
	for _, left := range windows {
		for _, right := range bounds {
			start := maxTime(left.Started, right.Started)
			end := minTime(left.Ended, right.Ended)
			if !end.After(start) {
				continue
			}
			intersections = append(intersections, sessionWindow{
				User:    left.User,
				Started: start,
				Ended:   end,
				Source:  joinWindowSources(left.Source, right.Source),
			})
		}
	}
	return mergeSessionWindows(intersections)
}

func minTime(left time.Time, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func maxTime(left time.Time, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}

func countOpenSessions(windows []sessionWindow) int {
	count := 0
	for _, window := range windows {
		if window.Open {
			count++
		}
	}
	return count
}

func summarizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return "activity"
	}
	const maxLen = 160
	if len(command) <= maxLen {
		return command
	}
	return strings.TrimSpace(command[:maxLen-3]) + "..."
}

func joinWindowSources(left string, right string) string {
	set := map[string]struct{}{}
	for _, item := range strings.Split(left, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			set[item] = struct{}{}
		}
	}
	for _, item := range strings.Split(right, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			set[item] = struct{}{}
		}
	}
	list := make([]string, 0, len(set))
	for item := range set {
		list = append(list, item)
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}

func formatTime(moment time.Time) string {
	if moment.IsZero() {
		return ""
	}
	return moment.Format(time.RFC3339)
}

func joinSources(sources map[string]struct{}) string {
	if len(sources) == 0 {
		return ""
	}
	list := make([]string, 0, len(sources))
	for source := range sources {
		list = append(list, source)
	}
	sort.Strings(list)
	return strings.Join(list, ", ")
}

func normalizeUser(user string) string {
	return strings.TrimSpace(user)
}

func detectWarnings(sections sectionedOutput) []string {
	var warnings []string
	if len(sections.Last) == 0 {
		warnings = append(warnings, "no data from last/wtmp")
	}
	if len(sections.Journal) == 0 && len(sections.AuthLog) == 0 {
		warnings = append(warnings, "no journalctl/auth log evidence collected")
	}
	if len(sections.History) == 0 && len(sections.Tmux) == 0 {
		warnings = append(warnings, "no readable shell history or tmux data collected")
	}
	return warnings
}
