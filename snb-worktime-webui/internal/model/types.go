package model

import "time"

type Snapshot struct {
	Server      string
	User        string
	SessionID   string
	State       string
	IdleSeconds int
	ClientIP    string
	ClientName  string
	CapturedAt  time.Time
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
