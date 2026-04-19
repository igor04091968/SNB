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
	Server    string
	ClientIP  string
	User      string
	StartedAt time.Time
	EndedAt   time.Time
	Source    string
}

type Config struct {
	ActiveIdleThreshold time.Duration
	MaxGap              time.Duration
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
