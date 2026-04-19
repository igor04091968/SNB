# Project Map

## Location

- Root: `/home/igor/SNB/snb-worktime-webui`

## Main Files

- `cmd/snb-worktime-webui/main.go`
  - process entrypoint
  - starts the HTTP server with `internal/web`
- `cmd/snb-worktime-collector/main.go`
  - Windows collector entrypoint
  - writes JSONL session snapshots to stdout or a file
- `cmd/snb-worktime-heartbeat/main.go`
  - Windows workstation heartbeat entrypoint
  - writes `activity windows` JSONL for unlocked, low-idle periods
- `internal/collector/wts/`
  - native Windows Terminal Services collector
  - enumerates sessions through WTS APIs
  - captures user, session id, state, idle time, client name, client IP, logon time
- `internal/collector/workstation/`
  - native Windows workstation-side collector
  - reads current username, local IP, idle time, and lock state
  - converts current workstation status into an `activity window`
- `internal/serverstore/`
  - local JSON-backed inventory for Linux SSH targets
  - stores SSH username, password, key, passphrase, and notes
- `internal/linuxaudit/`
  - SSH-based Linux audit runner
  - collects `last`, `who`, `journalctl`, `auth.log`, and `secure`
  - summarizes session minutes and evidence counts by user
- `internal/web/handler.go`
  - serves embedded static assets
  - exposes `/api/health`, `/api/analyze`, `/api/linux-servers`, `/api/linux-audit`
  - parses date-range and daily-interval filters from the UI
- `internal/web/static/`
  - embedded browser UI
  - `index.html`, `app.js`, `styles.css`
  - includes calendar-based date selection and default/operator interval controls
- `internal/timewindow/`
  - shared clipping logic for date ranges and per-day working intervals
- `internal/parser/jsonl.go`
  - tolerant JSONL parsing for snapshots and activity windows
  - accepts multiple field aliases
- `internal/worktime/calc.go`
  - core calculation logic
  - groups by server and user
  - splits worked, confirmed, unconfirmed, idle, disconnected, unknown
- `internal/worktime/calc_test.go`
  - focused tests for current calculation behavior
- `internal/model/types.go`
  - shared data structures
- `scripts/build-windows.sh`
  - convenience Windows build wrapper

## Standard Commands

- `go test ./...`
- `go run ./cmd/snb-worktime-webui`
- `GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-collector.exe ./cmd/snb-worktime-collector`
- `GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-heartbeat.exe ./cmd/snb-worktime-heartbeat`
- `GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-webui.exe ./cmd/snb-worktime-webui`

## Design Intent

- Use local files and pasted JSONL as the initial ingestion path.
- Keep the UI static and embedded so the Windows deployment is one executable.
- Use the native WTS collector as the primary source for server-side RDP activity snapshots.
- Use the native workstation heartbeat collector as the first confirmation layer from employee PCs.
- Use SSH-based Linux log collection as the infrastructure-side audit path for Linux hosts.
- Apply the same selected calendar range and effective daily interval to both local and Linux audit flows.
- Keep parser input flexible because upstream Windows and workstation collectors may differ.
- Keep the calculation transparent and auditable from raw events.

## Expected Next Extensions

- native Windows Event Log ingestion
- day-based aggregation and payroll export
- encrypted credential storage or OS keystore integration
- SQLite storage for imports and computed summaries
