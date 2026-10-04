#!/usr/bin/env bash
# Cross-compile ServerManagerAuthenticator.exe from Linux/macOS.
# Requires: Go 1.22+ (no CGO). Target: Windows amd64 (WebView2).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

OUT="${1:-ServerManagerAuthenticator.exe}"
export CGO_ENABLED=0
export GOOS=windows
export GOARCH=amd64

go mod tidy
# -H windowsgui: no console flash; WebView2 hosts the UI.
go build -trimpath -ldflags="-s -w -H windowsgui" -o "$OUT" .
sha256sum "$OUT" | tee "${OUT}.sha256"
file "$OUT"
echo "Built $ROOT/$OUT"
