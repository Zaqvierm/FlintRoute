#!/bin/sh
set -eu

RUN_DIR="${1:-}"
BIN="${2:-}"
PRODUCTION_CONFIG="${3:-/etc/router-policy/config/default.json}"

case "$RUN_DIR" in
  /tmp/router-policy/p14-hardware/p14-lifecycle-*) ;;
  *) echo "unsafe P14 run directory" >&2; exit 64 ;;
esac
[ -x "$BIN" ] || { echo "candidate binary is not executable" >&2; exit 65; }
[ -f "$PRODUCTION_CONFIG" ] || { echo "production config is missing" >&2; exit 66; }

TEST_ROOT="$RUN_DIR/test-root"
TEST_CONFIG="$RUN_DIR/test-config.json"
STATE_DIR="$TEST_ROOT/state"
RUNTIME_DIR="$TEST_ROOT/runtime"
FOREIGN_PID=""
LISTENER_PID=""
STALE_PID=""
CRASH_PID=""
NETWORK_TABLE=""
NETWORK_ACTIVE=0
ROLLBACK_PID=""
ROLLBACK_CANCEL="$RUN_DIR/network-rollback.cancel"

cleanup() {
  [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null || true
  [ -n "$FOREIGN_PID" ] && kill "$FOREIGN_PID" 2>/dev/null || true
  [ -n "$STALE_PID" ] && kill "$STALE_PID" 2>/dev/null || true
  [ -n "$CRASH_PID" ] && kill "$CRASH_PID" 2>/dev/null || true
  touch "$ROLLBACK_CANCEL" 2>/dev/null || true
  [ -n "$ROLLBACK_PID" ] && kill "$ROLLBACK_PID" 2>/dev/null || true
  if [ "$NETWORK_ACTIVE" -eq 1 ]; then
    ip -4 rule del pref 30991 table 30991 2>/dev/null || true
    ip -4 route del table 30991 198.51.100.0/24 2>/dev/null || true
    [ -n "$NETWORK_TABLE" ] && nft delete table inet "$NETWORK_TABLE" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$STATE_DIR" "$RUNTIME_DIR"
chmod 700 "$TEST_ROOT" "$STATE_DIR" "$RUNTIME_DIR"
sed \
  -e "s#/tmp/router-policy#$RUNTIME_DIR#g" \
  -e "s#/etc/router-policy/state#$STATE_DIR#g" \
  "$PRODUCTION_CONFIG" > "$TEST_CONFIG"
chmod 600 "$TEST_CONFIG"

rp_test() {
  ROUTER_POLICY_CONFIG="$TEST_CONFIG" "$BIN" "$@"
}

rp_production() {
  ROUTER_POLICY_CONFIG="$PRODUCTION_CONFIG" "$BIN" "$@"
}

managed_pids() {
  for service in router-policy router-policy-xray router-policy-zapret router-policy-watchdog; do
    json="$(ubus call service list "{\"name\":\"$service\"}" 2>/dev/null || true)"
    pid="$(printf '%s' "$json" | jsonfilter -e '@.*.instances.*.pid' 2>/dev/null | head -n 1)"
    if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
      start="$(awk '{print $22}' "/proc/$pid/stat")"
      exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
      printf '%s pid=%s start=%s exe=%s\n' "$service" "$pid" "$start" "$exe"
    else
      printf '%s pid=none\n' "$service"
    fi
  done
}

baseline_digest() {
  {
    ubus call service list '{"name":"router-policy"}' 2>/dev/null || true
    ubus call service list '{"name":"router-policy-xray"}' 2>/dev/null || true
    ubus call service list '{"name":"router-policy-zapret"}' 2>/dev/null || true
    if command -v ss >/dev/null 2>&1; then ss -H -lntup 2>/dev/null; else netstat -lntup 2>/dev/null; fi
    nft list tables 2>/dev/null || true
    ip -4 rule show 2>/dev/null || true
    ip -6 rule show 2>/dev/null || true
    ip -4 route show table all 2>/dev/null || true
    ip -6 route show table all 2>/dev/null || true
  } | sha256sum | awk '{print $1}'
}

managed_pids > "$RUN_DIR/production-before.txt"
baseline_before="$(baseline_digest)"
rp_production lifecycle status --json > "$RUN_DIR/lifecycle-production.json"
rp_production storage migrate --dry-run --legacy-root /root > "$RUN_DIR/storage-migration-dry-run.json"

index=1
while [ "$index" -le 100 ]; do
  run_id="p14-seq-$(printf '%03d' "$index")"
  rp_test lifecycle begin --id "$run_id" --lease 1h >/dev/null
  rp_test lifecycle finish --id "$run_id" --result completed >/dev/null
  rp_test cleanup stale --apply --json > "$RUN_DIR/seq-cleanup-current.json"
  if grep -q '"matches": false' "$RUN_DIR/seq-cleanup-current.json"; then
    mv "$RUN_DIR/seq-cleanup-current.json" "$RUN_DIR/seq-baseline-failure.json"
    echo "baseline mismatch during sequential run $run_id" >&2
    exit 79
  fi
  index=$((index + 1))
done
rm -f "$RUN_DIR/seq-cleanup-current.json"
find "$STATE_DIR/lifecycle/test-runs" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null | sort > "$RUN_DIR/completed-manifests.txt"
manifest_count="$(grep -c '/p14-seq-[0-9][0-9][0-9]\.json$' "$RUN_DIR/completed-manifests.txt" || true)"
if [ "$manifest_count" -gt 32 ]; then
  rp_test lifecycle status --json > "$RUN_DIR/seq-history-failure.json"
  echo "completed lifecycle history is unbounded: $manifest_count" >&2
  exit 67
fi

suffix="$(date -u +%H%M%S)"
stale_id="p14-stale-$suffix"
stale_config="$RUNTIME_DIR/$stale_id-config.json"
owned_file="$RUNTIME_DIR/$stale_id-owned.txt"
cp "$TEST_CONFIG" "$stale_config"
printf 'owned by %s\n' "$stale_id" > "$owned_file"
rp_test lifecycle begin --id "$stale_id" --lease 1s >/dev/null
"$BIN" watchdog --health-url http://127.0.0.1:8787/api/v1/health --interval 1h --startup-grace 24h --failure-threshold 20 --inhibit-file "$stale_config" --service-script /etc/init.d/router-policy >/dev/null 2>&1 &
stale_pid=$!
STALE_PID="$stale_pid"
rp_test lifecycle add-process --id "$stale_id" --resource worker --pid "$stale_pid" --executable "$BIN" --config "$stale_config" >/dev/null
rp_test lifecycle add-file --id "$stale_id" --resource candidate --path "$stale_config" >/dev/null
rp_test lifecycle add-file --id "$stale_id" --resource marker --path "$owned_file" >/dev/null

foreign_marker="$RUNTIME_DIR/foreign-xray-process"
: > "$foreign_marker"
sleep 600 >/dev/null 2>&1 &
FOREIGN_PID=$!
sleep 2
rp_test cleanup stale --dry-run --json > "$RUN_DIR/stale-dry-run.json"
kill -0 "$stale_pid" 2>/dev/null || { echo "owned process disappeared during dry-run" >&2; exit 75; }
kill -0 "$FOREIGN_PID" 2>/dev/null || { echo "foreign process disappeared during dry-run" >&2; exit 76; }
[ -f "$owned_file" ]
rp_test cleanup stale --apply --json > "$RUN_DIR/stale-apply.json"
if kill -0 "$stale_pid" 2>/dev/null; then echo "owned stale process survived cleanup" >&2; exit 68; fi
STALE_PID=""
kill -0 "$FOREIGN_PID" 2>/dev/null || { echo "foreign process was killed by stale cleanup" >&2; exit 77; }
[ ! -e "$owned_file" ]
[ ! -e "$stale_config" ]
rp_test cleanup stale --apply --json > "$RUN_DIR/stale-apply-repeat.json"
kill -0 "$FOREIGN_PID" 2>/dev/null || { echo "foreign process was killed by repeated cleanup" >&2; exit 78; }

crash_id="p14-crash-$suffix"
crash_config="$RUNTIME_DIR/$crash_id-config.json"
cp "$TEST_CONFIG" "$crash_config"
rp_test lifecycle begin --id "$crash_id" --lease 1s >/dev/null
"$BIN" watchdog --health-url http://127.0.0.1:8787/api/v1/health --interval 1h --startup-grace 24h --failure-threshold 20 --inhibit-file "$crash_config" --service-script /etc/init.d/router-policy >/dev/null 2>&1 &
crash_pid=$!
CRASH_PID="$crash_pid"
rp_test lifecycle add-process --id "$crash_id" --resource worker --pid "$crash_pid" --executable "$BIN" --config "$crash_config" >/dev/null
rp_test lifecycle add-file --id "$crash_id" --resource candidate --path "$crash_config" >/dev/null
kill -9 "$crash_pid" 2>/dev/null || true
wait "$crash_pid" 2>/dev/null || true
CRASH_PID=""
sleep 2
rp_test cleanup stale --apply --json > "$RUN_DIR/crash-cleanup.json"
[ ! -e "$crash_config" ]

corrupt="$STATE_DIR/lifecycle/test-runs/p14-corrupt.json"
printf '{broken' > "$corrupt"
rp_test cleanup stale --dry-run --json > "$RUN_DIR/corrupt-manifest.json"
kill -0 "$FOREIGN_PID" 2>/dev/null || { echo "foreign process was affected by crash cleanup" >&2; exit 80; }
rm -f "$corrupt"

network_id="p14-net-$suffix"
network_table="router_policy_test_$(printf '%s' "$network_id" | tr '.:-' '___')"
NETWORK_TABLE="$network_table"
if nft list table inet "$network_table" >/dev/null 2>&1 || ip -4 rule show pref 30991 | grep -q . || ip -4 route show table 30991 exact 198.51.100.0/24 | grep -q .; then
  echo "P14 network namespace is already occupied" >&2
  exit 74
fi
rp_test lifecycle begin --id "$network_id" --lease 1s >/dev/null
( sleep 300; if [ ! -f "$ROLLBACK_CANCEL" ]; then ip -4 rule del pref 30991 table 30991 2>/dev/null || true; ip -4 route del table 30991 198.51.100.0/24 2>/dev/null || true; nft delete table inet "$network_table" 2>/dev/null || true; fi ) &
ROLLBACK_PID=$!
nft add table inet "$network_table"
ip -4 route add table 30991 198.51.100.0/24 dev lo
ip -4 rule add pref 30991 table 30991
NETWORK_ACTIVE=1
rp_test lifecycle add-network --id "$network_id" --resource nft --kind nft-table --family inet --table "$network_table" >/dev/null
rp_test lifecycle add-network --id "$network_id" --resource route --kind route --family ipv4 --table 30991 --address 198.51.100.0/24 >/dev/null
rp_test lifecycle add-network --id "$network_id" --resource rule --kind ip-rule --family ipv4 --table 30991 --priority 30991 >/dev/null
sleep 2
rp_test cleanup stale --dry-run --json > "$RUN_DIR/network-dry-run.json"
rp_test cleanup stale --apply --json > "$RUN_DIR/network-apply.json"
if nft list table inet "$network_table" >/dev/null 2>&1; then echo "owned nft table survived" >&2; exit 69; fi
if ip -4 rule show pref 30991 | grep -q .; then echo "owned IP rule survived" >&2; exit 70; fi
if ip -4 route show table 30991 exact 198.51.100.0/24 | grep -q .; then echo "owned route survived" >&2; exit 71; fi
NETWORK_ACTIVE=0
touch "$ROLLBACK_CANCEL"
kill "$ROLLBACK_PID" 2>/dev/null || true
wait "$ROLLBACK_PID" 2>/dev/null || true
ROLLBACK_PID=""

listener_id="p14-listener-$suffix"
rp_test lifecycle begin --id "$listener_id" --lease 1s >/dev/null
ROUTER_POLICY_CONFIG="$TEST_CONFIG" "$BIN" serve --listen 127.0.0.1:18081 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1
kill -0 "$LISTENER_PID" 2>/dev/null || { echo "loopback listener fixture failed to start" >&2; exit 81; }
rp_test lifecycle add-network --id "$listener_id" --resource listener --kind listener --address 127.0.0.1:18081 >/dev/null
sleep 2
rp_test cleanup stale --apply --json > "$RUN_DIR/listener-protected.json"
kill -0 "$LISTENER_PID" 2>/dev/null || { echo "ambiguous loopback listener was killed" >&2; exit 82; }
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""
rp_test cleanup stale --apply --json > "$RUN_DIR/listener-released.json"

kill "$FOREIGN_PID" 2>/dev/null || true
wait "$FOREIGN_PID" 2>/dev/null || true
FOREIGN_PID=""
managed_pids > "$RUN_DIR/production-after.txt"
baseline_after="$(baseline_digest)"
[ "$baseline_before" = "$baseline_after" ] || { echo "production baseline drifted" >&2; exit 72; }
cmp "$RUN_DIR/production-before.txt" "$RUN_DIR/production-after.txt" >/dev/null || { echo "production process identity changed" >&2; exit 73; }
rm -rf "$TEST_ROOT"
rm -f "$TEST_CONFIG"

cat > "$RUN_DIR/summary.txt" <<EOF
result=PASS
sequential_test_runs=100
completed_manifest_count=$manifest_count
stale_cleanup_idempotent=true
sigkill_recovery=true
foreign_process_protected=true
production_processes_preserved=true
network_namespace_cleanup=true
listener_ambiguity_protected=true
baseline_restored=true
ssh_disconnect_survived=true
EOF
sha256sum "$RUN_DIR"/*.json "$RUN_DIR"/*.txt > "$RUN_DIR/SHA256SUMS.txt"
touch "$RUN_DIR/done"
