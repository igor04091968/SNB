#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -o dist/snb-worktime-webui.exe ./cmd/snb-worktime-webui
