# Project Map

## Location

- Root: `/home/igor/SNB/snb-worktime-webui`

## Main Files

- `cmd/snb-worktime-webui/main.go`
  - process entrypoint
  - starts the HTTP server with `internal/web`
- `internal/web/handler.go`
  - serves embedded static assets
  - exposes `/api/health` and `/api/analyze`
- `internal/web/static/`
  - embedded browser UI
  - `index.html`, `app.js`, `styles.css`
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
- `GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-webui.exe ./cmd/snb-worktime-webui`

## Design Intent

- Use local files and pasted JSONL as the initial ingestion path.
- Keep the UI static and embedded so the Windows deployment is one executable.
- Keep parser input flexible because upstream Windows and workstation collectors may differ.
- Keep the calculation transparent and auditable from raw events.

## Expected Next Extensions

- native Windows Event Log ingestion
- WTS or RDP session collector support
- day-based aggregation and payroll export
- SQLite storage for imports and computed summaries
