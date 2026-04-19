package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"snb-worktime-webui/internal/linuxaudit"
	"snb-worktime-webui/internal/model"
	"snb-worktime-webui/internal/parser"
	"snb-worktime-webui/internal/serverstore"
	"snb-worktime-webui/internal/worktime"
)

//go:embed static
var webFiles embed.FS

type App struct {
	store *serverstore.Store
}

type analyzeRequest struct {
	SnapshotsText       string `json:"snapshots_text"`
	ActivityWindowsText string `json:"activity_windows_text"`
	IdleThresholdSec    int    `json:"idle_threshold_sec"`
	MaxGapSec           int    `json:"max_gap_sec"`
	SinceDate           string `json:"since_date"`
	UntilDate           string `json:"until_date"`
	IntervalStart       string `json:"interval_start"`
	IntervalEnd         string `json:"interval_end"`
}

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	staticFiles := mustSubFS(webFiles, "static")
	app := &App{store: serverstore.New(defaultServerStorePath())}

	mux.Handle("/", http.FileServer(http.FS(staticFiles)))
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/analyze", app.handleAnalyze)
	mux.HandleFunc("/api/linux-servers", app.handleLinuxServers)
	mux.HandleFunc("/api/linux-audit", app.handleLinuxAudit)
	return withJSONDefaults(mux)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (app *App) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req analyzeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	snapshots, snapshotWarnings, err := parser.ParseSnapshotsJSONL(strings.NewReader(req.SnapshotsText))
	if err != nil {
		http.Error(w, "failed to parse snapshots", http.StatusBadRequest)
		return
	}
	if len(snapshots) == 0 {
		http.Error(w, "no valid snapshots found", http.StatusBadRequest)
		return
	}

	windows, activityWarnings, err := parser.ParseActivityWindowsJSONL(strings.NewReader(req.ActivityWindowsText))
	if err != nil {
		http.Error(w, "failed to parse activity windows", http.StatusBadRequest)
		return
	}

	cfg := model.Config{
		ActiveIdleThreshold: time.Duration(maxInt(req.IdleThresholdSec, 60)) * time.Second,
		MaxGap:              time.Duration(maxInt(req.MaxGapSec, 600)) * time.Second,
	}
	if err := applyDateIntervalFilters(&cfg, req.SinceDate, req.UntilDate, req.IntervalStart, req.IntervalEnd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := model.AnalyzeResponse{
		Rows:      worktime.Summarize(snapshots, windows, cfg),
		Warnings:  append(snapshotWarnings, activityWarnings...),
		Snapshots: len(snapshots),
		Windows:   len(windows),
	}
	writeJSON(w, http.StatusOK, response)
}

func (app *App) handleLinuxServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		servers, err := app.store.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"servers": servers})
	case http.MethodPost:
		var server model.LinuxServer
		if err := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&server); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		saved, err := app.store.Upsert(server)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if err := app.store.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *App) handleLinuxAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.LinuxAuditRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	servers, err := app.store.ByIDs(req.ServerIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(servers) == 0 {
		http.Error(w, "no Linux servers selected", http.StatusBadRequest)
		return
	}

	since, until, err := parseAuditWindow(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := model.Config{Since: since, Until: until}
	if err := applyDateIntervalFilters(&cfg, req.SinceDate, req.UntilDate, req.IntervalStart, req.IntervalEnd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, linuxaudit.Audit(servers, cfg))
}

func parseAuditWindow(req model.LinuxAuditRequest) (time.Time, time.Time, error) {
	until := time.Now().UTC()
	if strings.TrimSpace(req.Until) != "" {
		parsed, err := time.Parse(time.RFC3339, req.Until)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		until = parsed.UTC()
	}

	since := until.Add(-24 * time.Hour)
	if strings.TrimSpace(req.Since) != "" {
		parsed, err := time.Parse(time.RFC3339, req.Since)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		since = parsed.UTC()
	}

	if !until.After(since) {
		return time.Time{}, time.Time{}, fmt.Errorf("until must be after since")
	}
	return since, until, nil
}

func applyDateIntervalFilters(cfg *model.Config, sinceDate string, untilDate string, intervalStart string, intervalEnd string) error {
	if cfg == nil {
		return nil
	}

	if strings.TrimSpace(sinceDate) != "" {
		parsed, err := time.Parse("2006-01-02", sinceDate)
		if err != nil {
			return fmt.Errorf("invalid since_date")
		}
		cfg.Since = parsed.UTC()
	}
	if strings.TrimSpace(untilDate) != "" {
		parsed, err := time.Parse("2006-01-02", untilDate)
		if err != nil {
			return fmt.Errorf("invalid until_date")
		}
		cfg.Until = parsed.Add(24 * time.Hour).UTC()
	}
	if !cfg.Since.IsZero() && !cfg.Until.IsZero() && !cfg.Until.After(cfg.Since) {
		return fmt.Errorf("until_date must be on or after since_date")
	}

	if strings.TrimSpace(intervalStart) == "" && strings.TrimSpace(intervalEnd) == "" {
		return nil
	}
	startMinutes, err := parseClockMinutes(intervalStart)
	if err != nil {
		return fmt.Errorf("invalid interval_start")
	}
	endMinutes, err := parseClockMinutes(intervalEnd)
	if err != nil {
		return fmt.Errorf("invalid interval_end")
	}
	if endMinutes <= startMinutes {
		return fmt.Errorf("interval_end must be after interval_start")
	}

	cfg.DayStartMinutes = startMinutes
	cfg.DayEndMinutes = endMinutes
	return nil
}

func parseClockMinutes(value string) (int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, err
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func defaultServerStorePath() string {
	if value := strings.TrimSpace(os.Getenv("WORKTIME_SERVER_STORE")); value != "" {
		return value
	}
	return filepath.Join("state", "linux_servers.json")
}

func withJSONDefaults(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}

func maxInt(value int, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func mustSubFS(filesystem fs.FS, dir string) fs.FS {
	subtree, err := fs.Sub(filesystem, dir)
	if err != nil {
		panic(err)
	}
	return subtree
}
