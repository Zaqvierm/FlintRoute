#!/bin/sh
set -eu

plan="${1:-}"
state_dir="${STATE_DIR:-/tmp/router-policy/apply}"
apply="${APPLY:-0}"

if [ -z "$plan" ] || [ ! -f "$plan" ]; then
  echo "usage: apply-route-plan.sh PLAN_JSON" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

mkdir -p "$state_dir"

jq -e '
  type == "object"
  and (.domain | type == "string")
  and (.service | type == "string")
  and (.selected.route | type == "string")
  and (.selected.status | type == "string")
' "$plan" >/dev/null

snapshot="$state_dir/previous.json"
staged="$state_dir/staged.$$"

if [ -f "$state_dir/active.json" ]; then
  cp "$state_dir/active.json" "$snapshot"
fi

cp "$plan" "$staged"

if [ "$apply" != "1" ]; then
  rm -f "$staged"
  echo "dry_run=true"
  echo "would_stage=$plan"
  echo "would_snapshot=$snapshot"
  echo "would_apply_dns_nftset_routes=false"
  exit 0
fi

echo "real apply is intentionally disabled until Flint 2 diagnostics are reviewed" >&2
rm -f "$staged"
exit 3

