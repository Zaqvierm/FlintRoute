#!/bin/sh
set -eu

case "$(uname -s 2>/dev/null || true)" in
  Linux*) ;;
  *)
    echo "NOT RUN LOCALLY — requires Linux process groups/procfs for Zapret cleanup"
    exit 0
    ;;
esac

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-zapret-calibration-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
BIN="$TMP/bin"
RUNTIME="$TMP/runtime"
mkdir -p "$BIN" "$RUNTIME" "$TMP/catalog"

cat >"$BIN/timeout-coreutils" <<'SH'
#!/bin/sh
case "${1:-}" in
  ''|*[!0-9]*) ;;
  *) shift ;;
esac
exec "$@"
SH
ln -s "$BIN/timeout-coreutils" "$BIN/fake-timeout"
cat >"$BIN/id" <<'SH'
#!/bin/sh
[ "${1:-}" = "-u" ] && echo 0
SH
cat >"$BIN/router-policy" <<'SH'
#!/bin/sh
case "${1:-}" in
  maintenance) exit 0 ;;
  zapret-blockcheck-import)
    printf '%s\n' '{"catalog":{"version":1,"profiles":[{"id":"profile-test","provider":"zapret","provider_version":"v1","transports":["tcp"],"ports":[443],"strategy_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},"evidence":[]}'
    ;;
  *) exit 2 ;;
esac
SH
cat >"$BIN/nfqws" <<'SH'
#!/bin/sh
echo 'github version v1'
SH
cat >"$BIN/zapret-init" <<'SH'
#!/bin/sh
case "${1:-}" in
  running) exit 1 ;;
  start|stop) exit 0 ;;
  *) exit 2 ;;
esac
SH
cat >"$TMP/blockcheck.sh" <<'SH'
#!/bin/sh
[ "${SCANLEVEL:-}" = "force" ]
[ "${SKIP_DNSCHECK:-}" = "1" ]
[ "${DNSCACHE_observed_example_4_COUNT:-}" = "2" ]
[ "${DNSCACHE_observed_example_4_0:-}" = "203.0.113.10" ]
[ "${DNSCACHE_observed_example_4_1:-}" = "203.0.113.11" ]
echo '* SUMMARY'
SH
cat >"$BIN/ip" <<'SH'
#!/bin/sh
case "$*" in
  *route*) cat "$ROUTE_STATE" ;;
  *rule*) cat "$RULE_STATE" ;;
  *) exit 2 ;;
esac
SH
chmod +x "$BIN/timeout-coreutils" "$BIN/id" "$BIN/router-policy" "$BIN/nfqws" "$BIN/zapret-init" "$BIN/ip" "$TMP/blockcheck.sh"
printf '{}\n' >"$TMP/config.json"
printf 'default via 192.0.2.1\n' >"$TMP/routes.state"
printf '0: from all lookup local\n' >"$TMP/rules.state"

PATH="$BIN:$PATH" \
TIMEOUT_BIN=fake-timeout \
ROUTER_POLICY_CONFIG="$TMP/config.json" \
ROUTER_POLICY_BIN="$BIN/router-policy" \
NFQWS_BIN="$BIN/nfqws" \
ZAPRET_INIT="$BIN/zapret-init" \
ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
BLOCKCHECK_TIMEOUT=30 \
ZAPRET_CALIBRATION_IPV4=203.0.113.10,203.0.113.11 \
ROUTE_STATE="$TMP/routes.state" RULE_STATE="$TMP/rules.state" \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode exhaustive \
    --domain observed.example \
    --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck.sh" >"$TMP/result.json"

grep -F '"version":1' "$TMP/result.json" >/dev/null
[ ! -e "$RUNTIME/zapret-calibration.lock" ]

cat >"$TMP/blockcheck-failed.sh" <<'SH'
#!/bin/sh
echo 'provider probe failed at TLS check'
exit 7
SH
chmod +x "$TMP/blockcheck-failed.sh"
if PATH="$BIN:$PATH" \
  TIMEOUT_BIN=fake-timeout \
  ROUTER_POLICY_CONFIG="$TMP/config.json" \
  ROUTER_POLICY_BIN="$BIN/router-policy" \
  NFQWS_BIN="$BIN/nfqws" \
  ZAPRET_INIT="$BIN/zapret-init" \
  ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
  ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
  ROUTE_STATE="$TMP/routes.state" RULE_STATE="$TMP/rules.state" \
  BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode exhaustive \
    --domain observed.example \
    --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck-failed.sh" >"$TMP/failed.json" 2>"$TMP/failed.log"; then
  echo "failing blockcheck unexpectedly passed" >&2
  exit 1
fi
grep -F 'bounded diagnostic tail follows' "$TMP/failed.log" >/dev/null
grep -F 'provider probe failed at TLS check' "$TMP/failed.log" >/dev/null
[ ! -e "$RUNTIME/zapret-calibration.lock" ]
[ -d "$RUNTIME/zapret-calibration-failures" ]
failed_bundle=$(find "$RUNTIME/zapret-calibration-failures" -mindepth 1 -maxdepth 1 -type d -name 'failure.*' | head -n 1)
[ -n "$failed_bundle" ]
[ -s "$failed_bundle/status.env" ]
grep -Fx 'status=7' "$failed_bundle/status.env" >/dev/null
[ -s "$failed_bundle/report.tail" ]
grep -F 'provider probe failed at TLS check' "$failed_bundle/report.tail" >/dev/null

cat >"$TMP/blockcheck-route-leak.sh" <<'SH'
#!/bin/sh
printf 'leaked calibration route\n' >"$ROUTE_STATE"
exit 7
SH
chmod +x "$TMP/blockcheck-route-leak.sh"
if PATH="$BIN:$PATH" \
  TIMEOUT_BIN=fake-timeout \
  ROUTER_POLICY_CONFIG="$TMP/config.json" \
  ROUTER_POLICY_BIN="$BIN/router-policy" \
  NFQWS_BIN="$BIN/nfqws" \
  ZAPRET_INIT="$BIN/zapret-init" \
  ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
  ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
  ROUTE_STATE="$TMP/routes.state" RULE_STATE="$TMP/rules.state" \
  BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode exhaustive \
    --domain observed.example \
    --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck-route-leak.sh" >"$TMP/route-leak.json" 2>"$TMP/route-leak.log"; then
  echo "route-leaking blockcheck unexpectedly passed" >&2
  exit 1
fi
grep -F 'calibration cleanup changed routing tables' "$TMP/route-leak.log" >/dev/null
[ ! -e "$RUNTIME/zapret-calibration.lock" ]

cat >"$TMP/blockcheck-timeout.sh" <<'SH'
#!/bin/sh
echo 'last bounded strategy'
exit 124
SH
chmod +x "$TMP/blockcheck-timeout.sh"
if PATH="$BIN:$PATH" \
  TIMEOUT_BIN=fake-timeout \
  ROUTER_POLICY_CONFIG="$TMP/config.json" \
  ROUTER_POLICY_BIN="$BIN/router-policy" \
  NFQWS_BIN="$BIN/nfqws" \
  ZAPRET_INIT="$BIN/zapret-init" \
  ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
  ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
  ROUTE_STATE="$TMP/routes.state" RULE_STATE="$TMP/rules.state" \
  BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode exhaustive \
    --domain observed.example \
    --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck-timeout.sh" >"$TMP/timeout.json" 2>"$TMP/timeout.log"; then
  echo "timed out blockcheck unexpectedly passed" >&2
  exit 1
fi
grep -F 'upstream blockcheck timed out after 30s' "$TMP/timeout.log" >/dev/null
grep -F 'last bounded strategy' "$TMP/timeout.log" >/dev/null
[ ! -e "$RUNTIME/zapret-calibration.lock" ]
[ "$(find "$RUNTIME/zapret-calibration-failures" -mindepth 1 -maxdepth 1 -type d -name 'failure.*' | wc -l | tr -d ' ')" -le 3 ]

# The explicit exhaustive mode selects upstream force scanning and a separate
# long-running budget without executing the scan in this fixture.
PATH="$BIN:$PATH" TIMEOUT_BIN=fake-timeout \
  sh "$ROOT/scripts/calibrate-zapret.sh" --dry-run --mode exhaustive \
    --domain observed.example --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck.sh" >"$TMP/exhaustive-dry-run.txt"
grep -F 'calibration_mode=exhaustive' "$TMP/exhaustive-dry-run.txt" >/dev/null
grep -F 'scan_level=force' "$TMP/exhaustive-dry-run.txt" >/dev/null
grep -F 'timeout_seconds=21600' "$TMP/exhaustive-dry-run.txt" >/dev/null

if PATH="$BIN:$PATH" TIMEOUT_BIN=fake-timeout BLOCKCHECK_TIMEOUT=21601 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --dry-run --mode exhaustive \
    --domain observed.example --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck.sh" >"$TMP/invalid-timeout.txt" 2>"$TMP/invalid-timeout.log"; then
  echo "out-of-range blockcheck timeout unexpectedly passed" >&2
  exit 1
fi
grep -F 'blockcheck timeout must be between 1 and 21600 seconds' "$TMP/invalid-timeout.log" >/dev/null

# The upstream script is never a quick curated runner.  A direct quick apply
# must fail closed instead of silently widening the search space.
if PATH="$BIN:$PATH" TIMEOUT_BIN=fake-timeout \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode quick \
    --domain observed.example --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck.sh" >"$TMP/quick.txt" 2>"$TMP/quick.log"; then
  echo "upstream script unexpectedly accepted quick mode" >&2
  exit 1
fi
grep -F 'quick calibration requires the separate curated dataplane evidence runner' "$TMP/quick.log" >/dev/null


# A provider script may daemonize nfqws before timing out.  The calibration
# finally path must reap that exact executable rather than leaving PPid=1.
cp "$(command -v sleep)" "$TMP/nfqws"
cat >"$TMP/blockcheck-orphan.sh" <<'SH'
#!/bin/sh
setsid "$ORPHAN_NFQWS" 60 >/dev/null 2>&1 &
printf '%s\n' "$!" >"$ORPHAN_PID_FILE"
sleep 1
exit 124
SH
chmod +x "$TMP/blockcheck-orphan.sh" "$TMP/nfqws"
if PATH="$BIN:$PATH" \
  TIMEOUT_BIN=fake-timeout \
  ROUTER_POLICY_CONFIG="$TMP/config.json" \
  ROUTER_POLICY_BIN="$BIN/router-policy" \
  NFQWS_BIN="$BIN/nfqws" \
  ZAPRET_INIT="$BIN/zapret-init" \
  ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
  ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
  ROUTE_STATE="$TMP/routes.state" RULE_STATE="$TMP/rules.state" \
  BLOCKCHECK_TIMEOUT=30 \
  ORPHAN_NFQWS="$TMP/nfqws" \
  ORPHAN_PID_FILE="$TMP/orphan.pid" \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode exhaustive \
    --domain observed.example \
    --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck-orphan.sh" >"$TMP/orphan.json" 2>"$TMP/orphan.log"; then
  echo "orphaning blockcheck unexpectedly passed" >&2
  exit 1
fi
orphan_pid=$(cat "$TMP/orphan.pid")
orphan_state=$(awk '{print $3}' "/proc/$orphan_pid/stat" 2>/dev/null || true)
if kill -0 "$orphan_pid" 2>/dev/null && [ "$orphan_state" != "Z" ]; then
  echo "calibration left an orphan nfqws process" >&2
  kill -KILL "$orphan_pid" 2>/dev/null || true
  exit 1
fi
[ ! -e "$RUNTIME/zapret-calibration.lock" ]

# SIGTERM must still run the same ownership/network cleanup, but the cancelled
# calibration must not be reported as a successful operation.
cat >"$TMP/blockcheck-cancel.sh" <<'SH'
#!/bin/sh
sleep 60
SH
cat >"$TMP/nfqws-version" <<'SH'
#!/bin/sh
echo 'github version v1'
SH
chmod +x "$TMP/blockcheck-cancel.sh" "$TMP/nfqws-version"
PATH="$BIN:$PATH" \
  TIMEOUT_BIN=fake-timeout \
  ROUTER_POLICY_CONFIG="$TMP/config.json" \
  ROUTER_POLICY_BIN="$BIN/router-policy" \
  NFQWS_BIN="$TMP/nfqws-version" \
  ZAPRET_INIT="$BIN/zapret-init" \
  ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
  ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
  ROUTE_STATE="$TMP/routes.state" RULE_STATE="$TMP/rules.state" \
  BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply --mode exhaustive \
    --domain observed.example \
    --bundle-id auto-observed \
    --network-fingerprint sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --blockcheck "$TMP/blockcheck-cancel.sh" >"$TMP/cancel.json" 2>"$TMP/cancel.log" &
cancel_pid=$!
i=0
while [ ! -d "$RUNTIME/zapret-calibration.lock" ] && [ "$i" -lt 10 ]; do
  sleep 1
  i=$((i + 1))
done
[ -d "$RUNTIME/zapret-calibration.lock" ] || {
  echo "cancel fixture did not start calibration" >&2
  kill "$cancel_pid" 2>/dev/null || true
  wait "$cancel_pid" 2>/dev/null || true
  exit 1
}
kill -TERM "$cancel_pid"
if wait "$cancel_pid"; then
  echo "SIGTERM calibration unexpectedly passed" >&2
  exit 1
else
  cancel_status=$?
fi
[ "$cancel_status" -eq 143 ] || {
  echo "SIGTERM returned unexpected status: $cancel_status" >&2
  exit 1
}
[ ! -e "$RUNTIME/zapret-calibration.lock" ] || {
  echo "SIGTERM cleanup left calibration lock" >&2
  exit 1
}
echo "zapret_calibration_resolves_timeout_from_path=true"
echo "zapret_calibration_sigterm_is_nonzero=true"
