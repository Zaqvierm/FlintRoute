#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
GO="${GO:-$ROOT/.tools/go1.26.5/go/bin/go}"
[ -x "$GO" ] || { echo "Go toolchain missing: $GO" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is missing; install Node.js/npm to test the web UI" >&2; exit 1; }

cd "$ROOT"
npm run typecheck
npm run build
"$GO" test ./...
"$GO" vet ./...
sh scripts/build-go.sh
sh tests/installer-backup.sh
sh tests/adapter-rollback.sh
sh tests/openwrt-adapter-integration.sh
if command -v shellcheck >/dev/null 2>&1; then
  find . -type f \( -name '*.sh' -o -name 'router-policy' -o -name 'router-policy-watchdog' -o -name '95-router-policy' \) \
    ! -path './.tools/*' ! -path './.git/*' ! -path './.local/*' ! -path './dist/*' ! -path './node_modules/*' -print0 | xargs -0 shellcheck -x
else
  echo "shellcheck_missing=true"
fi
./dist/router-policy validate-config >/tmp/router-policy-validate.json
./dist/router-policy candidates chatgpt.com openai >/tmp/router-policy-candidates.json
./dist/router-policy subscription-normalize tests/sample-subscription-array.json >/tmp/router-policy-subscription-summary.json
./dist/router-policy subscription-routes tests/sample-subscription-array.json >/tmp/router-policy-subscription-routes.json
./dist/router-policy subscription-xray --out /tmp/router-policy-xray-test.json tests/sample-subscription-array.json >/tmp/router-policy-xray-summary.json
rm -f /tmp/router-policy-xray-test.json
cat > /tmp/router-policy-tspu-cache.json <<'JSON'
{
  "generated_at": "2026-07-11T12:00:00Z",
  "expires_at": "2999-01-01T00:00:00Z",
  "sources": [{"name":"fixture","url":"file://fixture","entries":3,"accepted":true,"confidence":0.9}],
  "entries": {
    "googlevideo.com": {
      "domain": "googlevideo.com",
      "source": "fixture",
      "confidence": 0.9,
      "first_seen": "2026-07-11T12:00:00Z",
      "last_seen": "2026-07-11T12:00:00Z"
    }
  }
}
JSON
./dist/router-policy tspu-check --cache /tmp/router-policy-tspu-cache.json rr1---sn.googlevideo.com >/tmp/router-policy-tspu-check.json
rm -f /tmp/router-policy-tspu-cache.json

if find README.md docs config scripts internal cmd openwrt tests ui package.json package-lock.json vite.config.ts tsconfig.json -type f ! -path 'tests/run-all.sh' ! -path 'tests/run-all.ps1' ! -path './tests/run-all.sh' ! -path './tests/run-all.ps1' ! -path './node_modules/*' -print0 |
  xargs -0 grep -E 'vless://|TELEGRAM_BOT_TOKEN=[A-Za-z0-9]|-----BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY-----|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' |
  grep -Ev 'UUID_PLACEHOLDER|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222|33333333-3333-4333-8333-333333333333'; then
  echo "secret-like values found" >&2
  exit 1
fi

if grep -R -E 'check_direct|check_zapret|check_smart_dns|check_vless|check_regional_direct|check_regional_zapret' scripts internal cmd; then
  echo "forbidden duplicated route check names found" >&2
  exit 1
fi

echo "all_tests_ok=true"
