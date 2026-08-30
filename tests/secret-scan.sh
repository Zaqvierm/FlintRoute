#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

# HWID values are device identifiers, not credentials. They are validated and
# deliberately shown in the HWID fixture/UI contract; URLs and tokens remain
# covered by the patterns below.
if find README.md SECURITY.md config docs scripts internal cmd openwrt tests ui package.json package-lock.json vite.config.ts tsconfig.json -type f \
  ! -path 'tests/run-all.sh' ! -path 'tests/run-all.ps1' ! -path './node_modules/*' \
  -print0 | xargs -0 grep -E 'TELEGRAM_BOT_TOKEN=[A-Za-z0-9]|-----BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY-----|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
  | grep -Ev 'UUID_PLACEHOLDER|a330268d-7d9d-4343-8672-f6191f80a25c|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222|33333333-3333-4333-8333-333333333333|44444444-4444-4444-8444-444444444444|55555555-5555-4555-8555-555555555555|66666666-6666-4666-8666-666666666666|77777777-7777-4777-8777-777777777777|88888888-8888-4888-8888-888888888888'; then
  echo "secret-like values found" >&2
  exit 1
fi

if grep -R -E 'check_direct|check_zapret|check_smart_dns|check_vless|check_regional_direct|check_regional_zapret' scripts internal cmd; then
  echo "forbidden duplicated route check names found" >&2
  exit 1
fi

echo "secret_scan=clean"
