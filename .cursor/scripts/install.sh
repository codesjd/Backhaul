#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

go mod download
go build -ldflags="-s -w" -o backhaul ./main.go
