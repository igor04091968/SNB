package web

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"snb-worktime-webui/internal/model"
	"snb-worktime-webui/internal/parser"
	"snb-worktime-webui/internal/worktime"
)

//go:embed static
var webFiles embed.FS

type analyzeRequest struct {
	SnapshotsText       string `json:"snapshots_text"`
	ActivityWindowsText string `json:"activity_windows_text"`
	IdleThresholdSec    int    `json:"idle_threshold_sec"`
	MaxGapSec           int    `json:"max_gap_sec"`
}

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	staticFiles := mustSubFS(webFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(staticFiles)))
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/analyze", handleAnalyze)
	return withJSONDefaults(mux)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
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

	response := model.AnalyzeResponse{
		Rows:      worktime.Summarize(snapshots, windows, cfg),
		Warnings:  append(snapshotWarnings, activityWarnings...),
		Snapshots: len(snapshots),
		Windows:   len(windows),
	}
	writeJSON(w, http.StatusOK, response)
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
