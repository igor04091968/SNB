package linuxaudit

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"snb-worktime-webui/internal/model"
	"snb-worktime-webui/internal/timewindow"
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

type sectionedOutput struct {
	HostName string
	Last     []string
	Who      []string
	Journal  []string
	AuthLog  []string
}

func Audit(servers []model.LinuxServer, cfg model.Config) model.LinuxAuditResponse {
	if cfg.Until.IsZero() {
		cfg.Until = time.Now().UTC()
	}
	if cfg.Since.IsZero() {
		cfg.Since = cfg.Until.Add(-24 * time.Hour)
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
			if response.Rows[i].Server == response.Rows[j].Server {
				return response.Rows[i].User < response.Rows[j].User
			}
			return response.Rows[i].Server < response.Rows[j].Server
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
	sessions := append(parseLastSessions(sections.Last, cfg.Until), parseWhoSessions(sections.Who, cfg.Until)...)
	evidence := append(parseJournalEvidence(sections.Journal, cfg.Since, cfg.Until), parseAuthEvidence(sections.AuthLog, cfg.Since, cfg.Until)...)

	byUser := map[string]*aggregate{}
	for _, session := range sessions {
		user := normalizeUser(session.User)
		if user == "" {
			continue
		}
		agg := ensureAggregate(byUser, user)
		agg.sessionCount++
		agg.sources[session.Source] = struct{}{}

		minutes := int64(timewindow.Duration(session.Started, session.Ended, cfg.Since, cfg.Until, cfg.DayStartMinutes, cfg.DayEndMinutes) / time.Minute)
		if minutes <= 0 {
			continue
		}
		agg.sessionMinutes += minutes
		if session.Open {
			agg.openMinutes += minutes
			agg.openSessions++
		}
		if clippedStart, clippedEnd, ok := timewindow.Clip(session.Started, session.Ended, cfg.Since, cfg.Until); ok {
			updateSeen(agg, clippedStart)
			updateSeen(agg, clippedEnd)
		}
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
			OpenMinutes:    agg.openMinutes,
			OpenHuman:      humanMinutes(agg.openMinutes),
			SessionCount:   agg.sessionCount,
			OpenSessions:   agg.openSessions,
			EvidenceCount:  agg.evidenceCount,
			SourceSummary:  joinSources(agg.sources),
			FirstSeen:      formatTime(agg.firstSeen),
			LastSeen:       formatTime(agg.lastSeen),
		})
	}

	return rows, detectWarnings(sections), nil
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
	var methods []ssh.AuthMethod
	if strings.TrimSpace(server.Password) != "" {
		methods = append(methods, ssh.Password(server.Password))
	}
	if strings.TrimSpace(server.PrivateKeyPEM) != "" {
		signer, err := parseSigner(server.PrivateKeyPEM, server.PrivateKeyPassphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth configured for %s", server.NameOrHost())
	}

	return &ssh.ClientConfig{
		User:            server.Username,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         12 * time.Second,
	}, nil
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
	openMinutes    int64
	sessionCount   int
	openSessions   int
	evidenceCount  int
	firstSeen      time.Time
	lastSeen       time.Time
	sources        map[string]struct{}
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
	return warnings
}
