package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"snb-worktime-webui/internal/model"
)

func ParseSnapshotsJSONL(r io.Reader) ([]model.Snapshot, []string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var out []model.Snapshot
	var warnings []string
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		item, err := parseSnapshotLine(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("snapshot line %d skipped: %v", lineNumber, err))
			continue
		}
		out = append(out, item)
	}

	if err := scanner.Err(); err != nil {
		return nil, warnings, err
	}
	return out, warnings, nil
}

func ParseActivityWindowsJSONL(r io.Reader) ([]model.ActivityWindow, []string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var out []model.ActivityWindow
	var warnings []string
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		item, err := parseWindowLine(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("activity line %d skipped: %v", lineNumber, err))
			continue
		}
		out = append(out, item)
	}

	if err := scanner.Err(); err != nil {
		return nil, warnings, err
	}
	return out, warnings, nil
}

func parseSnapshotLine(line string) (model.Snapshot, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return model.Snapshot{}, err
	}

	capturedAt, err := pickTime(raw,
		"captured_at", "capturedAt", "timestamp", "time", "snapshot_time",
	)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("captured_at: %w", err)
	}

	user := pickString(raw, "user", "username", "account", "sam_account_name")
	if user == "" {
		return model.Snapshot{}, fmt.Errorf("missing user")
	}

	return model.Snapshot{
		Server:      pickString(raw, "server", "host", "hostname", "rdp_host"),
		User:        user,
		SessionID:   pickString(raw, "session_id", "sessionId", "session", "sid"),
		State:       pickString(raw, "state", "session_state", "wts_state"),
		IdleSeconds: pickInt(raw, "idle_seconds", "idleSeconds", "idle", "idle_time_seconds"),
		ClientIP:    pickString(raw, "client_ip", "clientIp", "source_ip", "ip"),
		ClientName:  pickString(raw, "client_name", "clientName", "workstation", "device_name"),
		CapturedAt:  capturedAt,
	}, nil
}

func parseWindowLine(line string) (model.ActivityWindow, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return model.ActivityWindow{}, err
	}

	startedAt, err := pickTime(raw,
		"started_at", "startedAt", "window_start", "start", "from",
	)
	if err != nil {
		return model.ActivityWindow{}, fmt.Errorf("started_at: %w", err)
	}

	endedAt, err := pickTime(raw,
		"ended_at", "endedAt", "window_end", "end", "to",
	)
	if err != nil {
		return model.ActivityWindow{}, fmt.Errorf("ended_at: %w", err)
	}

	if !endedAt.After(startedAt) {
		return model.ActivityWindow{}, fmt.Errorf("ended_at must be after started_at")
	}

	return model.ActivityWindow{
		Server:    pickString(raw, "server", "host", "hostname"),
		ClientIP:  pickString(raw, "client_ip", "clientIp", "source_ip", "ip"),
		User:      pickString(raw, "user", "username"),
		StartedAt: startedAt,
		EndedAt:   endedAt,
		Source:    pickString(raw, "source", "source_type", "kind"),
	}, nil
}

func pickString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case float64:
			return strconv.FormatInt(int64(typed), 10)
		}
	}
	return ""
}

func pickInt(raw map[string]any, keys ...string) int {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int(typed)
		case string:
			number, err := strconv.Atoi(strings.TrimSpace(typed))
			if err == nil {
				return number
			}
		}
	}
	return 0
}

func pickTime(raw map[string]any, keys ...string) (time.Time, error) {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if parsed, err := parseTimeString(strings.TrimSpace(typed)); err == nil {
				return parsed, nil
			}
		case float64:
			seconds := int64(typed)
			return time.Unix(seconds, 0).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("no supported time field found")
}

func parseTimeString(value string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02T15:04:05",
	}

	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported time format %q", value)
}
