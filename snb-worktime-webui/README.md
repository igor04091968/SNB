# snb-worktime-webui

Go-based local web UI for employee worktime calculation from Windows and Linux infrastructure data.

## What is included

- embedded web UI served by the Go binary;
- JSONL parser for session snapshots from Windows / RDP hosts;
- native Windows WTS collector for real RDP session snapshots;
- native Windows workstation heartbeat collector for activity windows;
- Linux server inventory with SSH credentials and key-based auth;
- remote Linux worktime audit from `last`, `who`, `journalctl`, `auth.log`, and `secure` when available;
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
GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-collector.exe ./cmd/snb-worktime-collector
GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-heartbeat.exe ./cmd/snb-worktime-heartbeat
```

## Collect real Windows snapshots

Build the collector:

```bash
cd /home/igor/SNB/snb-worktime-webui
GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-collector.exe ./cmd/snb-worktime-collector
```

Run once on the Windows RDP host:

```powershell
.\snb-worktime-collector.exe -output C:\ProgramData\SnbWorktime\snapshots.jsonl -append
```

Recommended deployment:

1. Create `C:\ProgramData\SnbWorktime\`.
2. Copy `snb-worktime-collector.exe` there.
3. Create a Task Scheduler task that runs every minute with rights to query Terminal Services session data.
4. Append into `snapshots.jsonl`.
5. Feed that file into the web UI or later ingestion pipeline.

Collector output is JSONL with fields like:

```json
{"server":"rds-01","user":"alice","session_id":"7","state":"active","idle_seconds":12,"client_ip":"10.10.5.44","client_name":"WS-044","captured_at":"2026-04-19T08:15:00Z","logon_time":"2026-04-19T05:57:13Z"}
```

## Collect workstation activity windows

Build the workstation heartbeat collector:

```bash
cd /home/igor/SNB/snb-worktime-webui
GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-heartbeat.exe ./cmd/snb-worktime-heartbeat
```

Run once on a Windows workstation:

```powershell
.\snb-worktime-heartbeat.exe -output C:\ProgramData\SnbWorktime\activity-windows.jsonl -append
```

Recommended deployment:

1. Create `C:\ProgramData\SnbWorktime\`.
2. Copy `snb-worktime-heartbeat.exe` there.
3. Create a Task Scheduler task that runs every minute for the logged-in user.
4. Append into `activity-windows.jsonl`.
5. Load that JSONL into the web UI as `Activity windows`.

The heartbeat collector emits a window only when the workstation is unlocked and idle time is below threshold. Output looks like:

```json
{"server":"WS-044","client_ip":"10.10.5.44","user":"BANK\\alice","started_at":"2026-04-19T08:14:00Z","ended_at":"2026-04-19T08:15:00Z","source":"workstation-heartbeat","client_name":"WS-044","idle_seconds":12}
```

## Next logical steps

- add day grouping and payroll export;
- add richer workstation state sources such as lock/unlock event ingestion;
- persist raw imports and calculation results in SQLite.

## Linux server audit

The web UI now supports a local inventory of Linux servers with:

- host and port;
- SSH username;
- password auth;
- private key PEM auth;
- optional key passphrase;
- local notes for access specifics.

Inventory is stored locally in `state/linux_servers.json`.

### Remote audit sources

For each selected Linux server the backend attempts to collect and correlate:

- `last -F -w --time-format iso` from `wtmp`;
- `who -u` for current open sessions;
- `journalctl` lines related to `sshd`, `sudo`, `su`, and `systemd-logind`;
- `/var/log/auth.log` and `/var/log/secure` tails when readable.

If `sudo -n` is available, the collector automatically uses it to read more logs. If not, the audit still runs with the sources accessible to the SSH account.

### What the Linux audit reports

The Linux audit currently produces a journal-based summary per server and user:

- total session time from `last` and current `who` sessions;
- open-session time;
- session counts;
- evidence event count from `journalctl` and auth logs;
- first and last seen timestamps;
- source list used for the row.

This is an evidence-driven SSH/session audit, not an idle-aware desktop tracker. Without a Linux-side agent or shell history instrumentation, journal data can prove session presence and administrative activity, but not perfect keyboard-level active work time.
