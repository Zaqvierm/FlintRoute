#!/bin/sh
set -eu

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
echo '* SUMMARY'
SH
chmod +x "$BIN/timeout-coreutils" "$BIN/id" "$BIN/router-policy" "$BIN/nfqws" "$BIN/zapret-init" "$TMP/blockcheck.sh"
printf '{}\n' >"$TMP/config.json"

PATH="$BIN:$PATH" \
TIMEOUT_BIN=fake-timeout \
ROUTER_POLICY_CONFIG="$TMP/config.json" \
ROUTER_POLICY_BIN="$BIN/router-policy" \
NFQWS_BIN="$BIN/nfqws" \
ZAPRET_INIT="$BIN/zapret-init" \
ROUTER_POLICY_RUNTIME_DIR="$RUNTIME" \
ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json" \
BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply \
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
  BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply \
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
  BLOCKCHECK_TIMEOUT=30 \
  sh "$ROOT/scripts/calibrate-zapret.sh" --apply \
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
echo "zapret_calibration_resolves_timeout_from_path=true"
