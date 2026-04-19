---
name: snb-worktime-webui
description: "Work on the `snb-worktime-webui` project in the SNB repository: a Go application with an embedded web UI for calculating employee worktime from Windows session snapshots and workstation or network activity windows. Use when adding features, fixing bugs, adjusting parsing rules, changing calculation logic, refining the web UI, updating Windows build flow, or integrating new telemetry sources for this specific project."
---

# SNB Worktime WebUI

## Overview

Use this skill to work inside `/home/igor/SNB/snb-worktime-webui` with minimal rediscovery. The project is a local-first Go service that serves an embedded web interface and computes employee worktime from JSONL telemetry.

Read `references/project-map.md` before substantial changes.

## Workflow

1. Start in `/home/igor/SNB/snb-worktime-webui`.
2. Inspect `README.md`, then confirm the target area from `references/project-map.md`.
3. Keep the design local-first:
   - Go backend serves the UI directly.
   - Frontend assets stay embedded in the binary.
   - Windows remains the deployment target, even if development happens on Linux.
4. For parser or calculation changes, update or add focused tests in `internal/worktime` or adjacent packages.
5. Before finishing, run:
   - `go test ./...`
   - `GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-webui.exe ./cmd/snb-worktime-webui`

## Project Rules

- Preserve the current architecture: `cmd/` entrypoint, `internal/` packages, embedded assets under `internal/web/static`.
- Prefer extending the tolerant JSONL parser instead of hardcoding one exact upstream schema.
- Keep calculation behavior explicit and reproducible. If a rule changes, update tests and `README.md`.
- Do not commit generated Windows binaries or other build output.
- Treat `worked`, `confirmed`, `unconfirmed`, `idle`, `disconnected`, and `unknown` as separate categories. Do not silently merge them.

## Typical Tasks

- Add support for new snapshot field aliases from Windows collectors.
- Add workstation-side activity formats and map them into activity windows.
- Change idle and gap handling without breaking determinism.
- Extend the web UI for uploads, filtering, day grouping, or export.
- Add persistence, such as SQLite, without turning the app into a remote-first service by default.

## References

- Use `references/project-map.md` for layout, commands, and change points.
