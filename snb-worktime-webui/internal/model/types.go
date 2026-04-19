package model

import "time"

type Snapshot struct {
	Server      string    `json:"server"`
	User        string    `json:"user"`
	SessionID   string    `json:"session_id"`
	State       string    `json:"state"`
	IdleSeconds int       `json:"idle_seconds"`
	ClientIP    string    `json:"client_ip,omitempty"`
	ClientName  string    `json:"client_name,omitempty"`
	CapturedAt  time.Time `json:"captured_at"`
	LogonTime   time.Time `json:"logon_time,omitempty"`
}

type ActivityWindow struct {
	Server      string    `json:"server"`
	ClientIP    string    `json:"client_ip,omitempty"`
	User        string    `json:"user,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	Source      string    `json:"source,omitempty"`
	ClientName  string    `json:"client_name,omitempty"`
	IdleSeconds int       `json:"idle_seconds,omitempty"`
	Locked      bool      `json:"locked,omitempty"`
}

type Config struct {
	ActiveIdleThreshold time.Duration
	MaxGap              time.Duration
	Since               time.Time
	Until               time.Time
	DayStartMinutes     int
	DayEndMinutes       int
	Location            *time.Location `json:"-"`
}

type Summary struct {
	Server              string        `json:"server"`
	User                string        `json:"user"`
	Worked              time.Duration `json:"-"`
	WorkedHuman         string        `json:"worked_human"`
	WorkedMinutes       int64         `json:"worked_minutes"`
	Confirmed           time.Duration `json:"-"`
	ConfirmedHuman      string        `json:"confirmed_human"`
	ConfirmedMinutes    int64         `json:"confirmed_minutes"`
	Unconfirmed         time.Duration `json:"-"`
	UnconfirmedHuman    string        `json:"unconfirmed_human"`
	UnconfirmedMinutes  int64         `json:"unconfirmed_minutes"`
	Idle                time.Duration `json:"-"`
	IdleHuman           string        `json:"idle_human"`
	IdleMinutes         int64         `json:"idle_minutes"`
	Disconnected        time.Duration `json:"-"`
	DisconnectedHuman   string        `json:"disconnected_human"`
	DisconnectedMinutes int64         `json:"disconnected_minutes"`
	Unknown             time.Duration `json:"-"`
	UnknownHuman        string        `json:"unknown_human"`
	UnknownMinutes      int64         `json:"unknown_minutes"`
	Samples             int           `json:"samples"`
}

type AnalyzeResponse struct {
	Rows      []Summary `json:"rows"`
	Warnings  []string  `json:"warnings"`
	Snapshots int       `json:"snapshots"`
	Windows   int       `json:"windows"`
}

type LinuxServer struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Host                 string    `json:"host"`
	Port                 int       `json:"port"`
	Username             string    `json:"username"`
	Password             string    `json:"password,omitempty"`
	PrivateKeyPEM        string    `json:"private_key_pem,omitempty"`
	PrivateKeyPassphrase string    `json:"private_key_passphrase,omitempty"`
	Notes                string    `json:"notes,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type LinuxAuditRequest struct {
	ServerIDs     []string `json:"server_ids"`
	Since         string   `json:"since"`
	Until         string   `json:"until"`
	SinceDate     string   `json:"since_date"`
	UntilDate     string   `json:"until_date"`
	IntervalStart string   `json:"interval_start"`
	IntervalEnd   string   `json:"interval_end"`
}

type LinuxAuditRow struct {
	Server         string               `json:"server"`
	User           string               `json:"user"`
	SessionMinutes int64                `json:"session_minutes"`
	SessionHuman   string               `json:"session_human"`
	OpenMinutes    int64                `json:"open_minutes"`
	OpenHuman      string               `json:"open_human"`
	SessionCount   int                  `json:"session_count"`
	OpenSessions   int                  `json:"open_sessions"`
	EvidenceCount  int                  `json:"evidence_count"`
	SourceSummary  string               `json:"source_summary"`
	FirstSeen      string               `json:"first_seen,omitempty"`
	LastSeen       string               `json:"last_seen,omitempty"`
	HasSessions    bool                 `json:"has_sessions"`
	Intervals      []LinuxAuditInterval `json:"intervals,omitempty"`
}

type LinuxAuditResponse struct {
	Rows            []LinuxAuditRow `json:"rows"`
	Warnings        []string        `json:"warnings"`
	ScannedServers  int             `json:"scanned_servers"`
	SuccessfulHosts int             `json:"successful_hosts"`
}

type LinuxAuditInterval struct {
	StartedAt       string `json:"started_at"`
	EndedAt         string `json:"ended_at"`
	DurationMinutes int64  `json:"duration_minutes"`
	DurationHuman   string `json:"duration_human"`
	Open            bool   `json:"open"`
	SourceSummary   string `json:"source_summary"`
}

func (server LinuxServer) NameOrHost() string {
	if server.Name != "" {
		return server.Name
	}
	return server.Host
}

func (server LinuxServer) DisplayName(remoteHost string) string {
	if server.Name != "" {
		return server.Name
	}
	if remoteHost != "" {
		return remoteHost
	}
	return server.Host
}

func (server LinuxServer) PortOrDefault() int {
	if server.Port > 0 {
		return server.Port
	}
	return 22
}
