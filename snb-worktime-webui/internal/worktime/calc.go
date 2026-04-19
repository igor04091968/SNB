package worktime

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"snb-worktime-webui/internal/model"
)

type identity struct {
	server string
	user   string
}

func Summarize(snapshots []model.Snapshot, windows []model.ActivityWindow, cfg model.Config) []model.Summary {
	if cfg.ActiveIdleThreshold <= 0 {
		cfg.ActiveIdleThreshold = time.Minute
	}
	if cfg.MaxGap <= 0 {
		cfg.MaxGap = 10 * time.Minute
	}

	groupedSnapshots := make(map[identity][]model.Snapshot)
	for _, snapshot := range snapshots {
		if snapshot.User == "" || snapshot.CapturedAt.IsZero() {
			continue
		}
		key := identity{
			server: strings.TrimSpace(snapshot.Server),
			user:   strings.ToLower(strings.TrimSpace(snapshot.User)),
		}
		groupedSnapshots[key] = append(groupedSnapshots[key], snapshot)
	}

	windowIndex := indexWindows(windows)

	var rows []model.Summary
	for key, group := range groupedSnapshots {
		sort.Slice(group, func(i, j int) bool {
			if group[i].CapturedAt.Equal(group[j].CapturedAt) {
				return group[i].SessionID < group[j].SessionID
			}
			return group[i].CapturedAt.Before(group[j].CapturedAt)
		})

		row := model.Summary{
			Server:  key.server,
			User:    key.user,
			Samples: len(group),
		}

		for index := 0; index < len(group)-1; index++ {
			current := group[index]
			next := group[index+1]
			delta := next.CapturedAt.Sub(current.CapturedAt)
			if delta <= 0 {
				continue
			}
			if delta > cfg.MaxGap {
				row.Unknown += delta
				continue
			}

			switch normalizeState(current.State) {
			case "active":
				if time.Duration(current.IdleSeconds)*time.Second <= cfg.ActiveIdleThreshold {
					row.Worked += delta
					if overlapsActivity(current, next.CapturedAt, windowIndex) {
						row.Confirmed += delta
					} else {
						row.Unconfirmed += delta
					}
				} else {
					row.Idle += delta
				}
			case "disconnected":
				row.Disconnected += delta
			default:
				row.Unknown += delta
			}
		}

		row.WorkedHuman = humanDuration(row.Worked)
		row.WorkedMinutes = int64(row.Worked / time.Minute)
		row.ConfirmedHuman = humanDuration(row.Confirmed)
		row.ConfirmedMinutes = int64(row.Confirmed / time.Minute)
		row.UnconfirmedHuman = humanDuration(row.Unconfirmed)
		row.UnconfirmedMinutes = int64(row.Unconfirmed / time.Minute)
		row.IdleHuman = humanDuration(row.Idle)
		row.IdleMinutes = int64(row.Idle / time.Minute)
		row.DisconnectedHuman = humanDuration(row.Disconnected)
		row.DisconnectedMinutes = int64(row.Disconnected / time.Minute)
		row.UnknownHuman = humanDuration(row.Unknown)
		row.UnknownMinutes = int64(row.Unknown / time.Minute)

		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Worked == rows[j].Worked {
			if rows[i].Server == rows[j].Server {
				return rows[i].User < rows[j].User
			}
			return rows[i].Server < rows[j].Server
		}
		return rows[i].Worked > rows[j].Worked
	})

	return rows
}

func indexWindows(windows []model.ActivityWindow) map[identity][]model.ActivityWindow {
	index := make(map[identity][]model.ActivityWindow)
	for _, window := range windows {
		if window.StartedAt.IsZero() || window.EndedAt.IsZero() || !window.EndedAt.After(window.StartedAt) {
			continue
		}
		if window.User != "" {
			key := identity{
				server: strings.TrimSpace(window.Server),
				user:   strings.ToLower(strings.TrimSpace(window.User)),
			}
			index[key] = append(index[key], window)
		}
		if window.ClientIP != "" {
			key := identity{
				server: strings.TrimSpace(window.Server),
				user:   "ip:" + strings.TrimSpace(window.ClientIP),
			}
			index[key] = append(index[key], window)
		}
	}
	return index
}

func overlapsActivity(snapshot model.Snapshot, end time.Time, index map[identity][]model.ActivityWindow) bool {
	keys := []identity{
		{server: strings.TrimSpace(snapshot.Server), user: strings.ToLower(strings.TrimSpace(snapshot.User))},
	}
	if snapshot.ClientIP != "" {
		keys = append(keys, identity{
			server: strings.TrimSpace(snapshot.Server),
			user:   "ip:" + strings.TrimSpace(snapshot.ClientIP),
		})
	}

	for _, key := range keys {
		for _, window := range index[key] {
			if snapshot.CapturedAt.Before(window.EndedAt) && end.After(window.StartedAt) {
				return true
			}
		}
	}
	return false
}

func normalizeState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active", "wtsactive":
		return "active"
	case "disc", "disconnected", "wtsdisconnected":
		return "disconnected"
	default:
		return "unknown"
	}
}

func humanDuration(value time.Duration) string {
	if value <= 0 {
		return "0m"
	}

	totalMinutes := int64(value / time.Minute)
	hours := totalMinutes / 60
	minutes := totalMinutes % 60
	if hours == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}
