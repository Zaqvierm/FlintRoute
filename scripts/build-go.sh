#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
GO="${GO:-}"
if [ -z "$GO" ]; then
  if command -v go >/dev/null 2>&1; then
    GO="$(command -v go)"
  else
    GO="$ROOT/.tools/go1.26.5/go/bin/go"
  fi
fi
[ -x "$GO" ] || { echo "Go toolchain not found. Set GO, add go to PATH, or install under .tools/" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is missing; install Node.js/npm to build the embedded web UI" >&2; exit 1; }

mkdir -p "$ROOT/dist"
(cd "$ROOT" && npm run typecheck && npm run build)
"$GO" test ./...
"$GO" build -o "$ROOT/dist/router-policy" ./cmd/router-policy
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$GO" build -trimpath -ldflags="-s -w" -o "$ROOT/dist/router-policy-linux-arm64" ./cmd/router-policy

ls -l "$ROOT/dist"
