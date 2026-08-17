#!/bin/sh
set -eu

CONFIG="${ROUTER_POLICY_CONFIG:-/etc/router-policy/config/default.json}"
ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-/usr/bin/router-policy}"
NFQWS_BIN="${NFQWS_BIN:-/usr/bin/nfqws}"
ZAPRET_INIT="${ZAPRET_INIT:-/etc/init.d/router-policy-zapret}"
RUNTIME_DIR="${ROUTER_POLICY_RUNTIME_DIR:-/tmp/router-policy}"
CATALOG_OUT="${ZAPRET_CATALOG_OUT:-/etc/router-policy/zapret/catalog.json}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
BLOCKCHECK_TIMEOUT="${BLOCKCHECK_TIMEOUT:-2400}"
QUEUE_NUM="${ZAPRET_QUEUE_NUM:-200}"

mode="dry-run"
domain=""
bundle_id=""
network_fingerprint=""
blockcheck_script="${BLOCKCHECK_SCRIPT:-}"
allow_managed_restart=0

usage() {
  echo "usage: calibrate-zapret.sh [--dry-run|--apply] --domain DOMAIN --bundle-id ID --network-fingerprint sha256:HEX --blockcheck FILE [--allow-managed-restart]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) mode="dry-run" ;;
    --apply) mode="apply" ;;
    --domain) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; domain="$1" ;;
    --bundle-id) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; bundle_id="$1" ;;
    --network-fingerprint) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; network_fingerprint="$1" ;;
    --blockcheck) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; blockcheck_script="$1" ;;
    --allow-managed-restart) allow_managed_restart=1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

case "$domain" in
  ""|.*|-*|*..*|*[!A-Za-z0-9.-]*) echo "invalid calibration domain" >&2; exit 2 ;;
esac
[ "${#domain}" -le 253 ] || { echo "calibration domain is too long" >&2; exit 2; }
case "$bundle_id" in
  ""|*[!A-Za-z0-9._-]*) echo "invalid calibration bundle ID" >&2; exit 2 ;;
esac
[ "${#bundle_id}" -le 96 ] || { echo "calibration bundle ID is too long" >&2; exit 2; }
case "$QUEUE_NUM" in
  ""|*[!0-9]*) echo "invalid Zapret queue number" >&2; exit 2 ;;
esac
[ "$QUEUE_NUM" -ge 1 ] && [ "$QUEUE_NUM" -le 65535 ] || { echo "invalid Zapret queue number" >&2; exit 2; }
case "$network_fingerprint" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "network fingerprint must be a sha256 digest" >&2; exit 2 ;;
esac
fingerprint_hex=${network_fingerprint#sha256:}
case "$fingerprint_hex" in
  *[!0-9a-fA-F]*) echo "network fingerprint must be hexadecimal" >&2; exit 2 ;;
esac
[ -n "$blockcheck_script" ] || { echo "upstream blockcheck path is required" >&2; exit 2; }

if [ "$mode" = "dry-run" ]; then
  echo "mode=dry-run"
  echo "domain=$domain"
  echo "bundle_id=$bundle_id"
  echo "would_run_upstream_blockcheck=$blockcheck_script"
  echo "would_store_top_candidates=$CATALOG_OUT"
  echo "would_not_activate_candidate=true"
  exit 0
fi

[ "$(id -u)" = "0" ] || { echo "Zapret calibration requires root" >&2; exit 1; }
case "$TIMEOUT_BIN" in
  /*) ;;
  *)
    resolved_timeout=$(command -v "$TIMEOUT_BIN") || {
      echo "required executable is unavailable: $TIMEOUT_BIN" >&2
      exit 1
    }
    TIMEOUT_BIN="$resolved_timeout"
    ;;
esac
if [ -L "$TIMEOUT_BIN" ]; then
  resolved_timeout=$(readlink -f "$TIMEOUT_BIN") || {
    echo "unable to resolve timeout executable: $TIMEOUT_BIN" >&2
    exit 1
  }
  TIMEOUT_BIN="$resolved_timeout"
fi
for command in "$ROUTER_POLICY_BIN" "$NFQWS_BIN" "$TIMEOUT_BIN"; do
  [ -x "$command" ] || { echo "required executable is unavailable: $command" >&2; exit 1; }
  [ ! -L "$command" ] || { echo "refusing symlink executable: $command" >&2; exit 1; }
done
[ -f "$blockcheck_script" ] && [ ! -L "$blockcheck_script" ] || {
  echo "upstream blockcheck must be a regular non-symlink file" >&2
  exit 1
}
[ -x "$ZAPRET_INIT" ] || { echo "FlintRoute Zapret service is unavailable" >&2; exit 1; }

mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
lock_dir="$RUNTIME_DIR/zapret-calibration.lock"
mkdir "$lock_dir" 2>/dev/null || { echo "another Zapret calibration is active" >&2; exit 1; }
run_dir="$RUNTIME_DIR/zapret-calibration.$$"
mkdir "$run_dir"
chmod 700 "$run_dir"
report="$run_dir/blockcheck.log"
result="$run_dir/import.json"
maintenance_started=0
zapret_was_running=0

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$zapret_was_running" = "1" ]; then
    "$TIMEOUT_BIN" 30 "$ZAPRET_INIT" start >/dev/null 2>&1 || status=1
  fi
  if [ "$maintenance_started" = "1" ]; then
    ROUTER_POLICY_CONFIG="$CONFIG" "$TIMEOUT_BIN" 15 "$ROUTER_POLICY_BIN" maintenance end >/dev/null 2>&1 || status=1
  fi
  rm -rf "$run_dir"
  rmdir "$lock_dir" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

if "$TIMEOUT_BIN" 10 "$ZAPRET_INIT" running >/dev/null 2>&1; then
  [ "$allow_managed_restart" = "1" ] || {
    echo "managed Zapret is active; repeat with --allow-managed-restart during a maintenance window" >&2
    exit 1
  }
  zapret_was_running=1
fi

ROUTER_POLICY_CONFIG="$CONFIG" "$TIMEOUT_BIN" 15 "$ROUTER_POLICY_BIN" maintenance begin \
  --owner "installer:zapret-calibration" --reason "provider-specific Zapret calibration" --lease 45m >/dev/null
maintenance_started=1

if [ "$zapret_was_running" = "1" ]; then
  "$TIMEOUT_BIN" 30 "$ZAPRET_INIT" stop
fi

provider_version=$("$TIMEOUT_BIN" 10 "$NFQWS_BIN" --version 2>&1 | sed -n '1p' | tr -cd 'A-Za-z0-9._+-' | cut -c1-64)
[ -n "$provider_version" ] || { echo "unable to determine nfqws version" >&2; exit 1; }

set +e
(
  cd "$(dirname "$blockcheck_script")"
  BATCH=1 IPVS=4 REPEATS=3 SCANLEVEL=standard SKIP_TPWS=1 DOMAINS="$domain" \
    "$TIMEOUT_BIN" "$BLOCKCHECK_TIMEOUT" sh "$blockcheck_script" >"$report" 2>&1
)
blockcheck_status=$?
set -e
if [ "$blockcheck_status" -ne 0 ]; then
  if [ "$blockcheck_status" -eq 124 ]; then
    echo "upstream blockcheck timed out after ${BLOCKCHECK_TIMEOUT}s; bounded diagnostic tail follows" >&2
  else
    echo "upstream blockcheck failed with exit ${blockcheck_status}; bounded diagnostic tail follows" >&2
  fi
  tail -n 12 "$report" | tr '\r\n\t' '   ' | cut -c1-1024 >&2
  exit "$blockcheck_status"
fi

ROUTER_POLICY_CONFIG="$CONFIG" "$TIMEOUT_BIN" 30 "$ROUTER_POLICY_BIN" zapret-blockcheck-import \
  --report "$report" \
  --binary "$NFQWS_BIN" \
  --provider-version "$provider_version" \
  --queue "$QUEUE_NUM" \
  --domain "$domain" \
  --bundle-id "$bundle_id" \
  --network-fingerprint "$network_fingerprint" \
  --catalog-out "$CATALOG_OUT" \
  --save >"$result"

# The API runner consumes one bounded JSON document. The report itself stays
# private in the run directory and is removed by cleanup.
cat "$result"
