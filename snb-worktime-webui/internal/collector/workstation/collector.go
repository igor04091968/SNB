package workstation

import (
	"time"

	"snb-worktime-webui/internal/model"
)

type Status struct {
	Server      string
	User        string
	ClientIP    string
	ClientName  string
	IdleSeconds int
	Locked      bool
	CapturedAt  time.Time
}

type Collector interface {
	Status() (Status, error)
}

func BuildActivityWindow(status Status, windowDuration time.Duration, idleThreshold time.Duration) (model.ActivityWindow, bool) {
	if status.Server == "" || status.User == "" || status.CapturedAt.IsZero() {
		return model.ActivityWindow{}, false
	}
	if windowDuration <= 0 {
		windowDuration = time.Minute
	}
	if idleThreshold <= 0 {
		idleThreshold = time.Minute
	}
	if status.Locked || time.Duration(status.IdleSeconds)*time.Second > idleThreshold {
		return model.ActivityWindow{}, false
	}

	return model.ActivityWindow{
		Server:      status.Server,
		ClientIP:    status.ClientIP,
		User:        status.User,
		StartedAt:   status.CapturedAt.Add(-windowDuration),
		EndedAt:     status.CapturedAt,
		Source:      "workstation-heartbeat",
		ClientName:  status.ClientName,
		IdleSeconds: status.IdleSeconds,
		Locked:      status.Locked,
	}, true
}
