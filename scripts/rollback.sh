#!/bin/sh
set -eu

config="${1:-}"
transaction_id="${2:-}"
revision_id="${3:-}"
ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/common.sh
. "$ROOT/scripts/lib/common.sh"

[ -n "$config" ] || config="$(rp_default_config)"
adapter="${ROUTER_POLICY_ADAPTER:-/usr/lib/router-policy/openwrt/adapter.sh}"

[ -n "$transaction_id" ] && [ -n "$revision_id" ] || {
  echo "usage: rollback.sh CONFIG TRANSACTION_ID REVISION_ID" >&2
  exit 2
}
[ -x "$adapter" ] || {
  echo "rollback adapter is missing or not executable: $adapter" >&2
  exit 1
}

exec "$adapter" rollback "$config" "$transaction_id" "$revision_id"
