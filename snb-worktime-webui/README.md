# snb-worktime-webui

Go-based local web UI for employee worktime calculation from Windows server and workstation data.

## What is included

- embedded web UI served by the Go binary;
- JSONL parser for session snapshots from Windows / RDP hosts;
- optional activity confirmation windows from workstations, network logs, or other sources;
- deterministic worktime summary by user and server;
- Windows build path for running as a standalone `.exe`.

## Input model

### Session snapshots

One JSON object per line. Minimal fields:

```json
{"server":"srv-1","user":"alice","state":"active","idle_seconds":5,"captured_at":"2026-04-18T09:00:00Z"}
```

Supported aliases:

- `user`, `username`
- `session_id`, `sessionId`
- `state`, `session_state`
- `idle_seconds`, `idleSeconds`
- `captured_at`, `capturedAt`, `timestamp`
- `client_ip`, `clientIp`

### Activity windows

Optional JSONL file for confirmation from workstations or network telemetry:

```json
{"server":"srv-1","client_ip":"10.0.0.10","started_at":"2026-04-18T09:00:00Z","ended_at":"2026-04-18T09:02:30Z","source":"workstation"}
```

The calculator matches activity by `user` or `client_ip`.

## Rule

- `active` + idle below threshold => counted as worked time
- `active` + idle above threshold => counted as idle time
- `disconnected` => counted as disconnected time
- gaps above configured threshold => counted as unknown time
- overlapping activity windows => mark worked time as confirmed

## Run locally

```bash
cd /home/igor/SNB/snb-worktime-webui
go run ./cmd/snb-worktime-webui
```

Then open `http://127.0.0.1:8080`.

## Build for Windows

```bash
cd /home/igor/SNB/snb-worktime-webui
GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-webui.exe ./cmd/snb-worktime-webui
```

## Next logical steps

- add native collectors for Windows Event Log and RDP session APIs;
- add day grouping and payroll export;
- add ingestion from workstation heartbeat data;
- persist raw imports and calculation results in SQLite.
