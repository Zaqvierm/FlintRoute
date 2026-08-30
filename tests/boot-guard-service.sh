#!/bin/sh
# The init script is sourced through a test-controlled absolute ROOT path.
# ShellCheck cannot resolve that runtime path in CI; the fixture owns the
# sourced file and exercises it explicitly below.
# shellcheck disable=SC1091
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-boot-guard-service-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP"

cat > "$TMP/adapter" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$BOOT_GUARD_CALL_LOG"
SH
chmod +x "$TMP/adapter"

procd_open_instance() {
  printf 'open:%s\n' "$*" >> "$PROCD_CALL_LOG"
}
procd_set_param() {
  printf 'param:%s\n' "$*" >> "$PROCD_CALL_LOG"
}
procd_close_instance() {
  printf 'close\n' >> "$PROCD_CALL_LOG"
}

BOOT_GUARD_CALL_LOG="$TMP/adapter.log"
PROCD_CALL_LOG="$TMP/procd.log"
ROUTER_POLICY_ADAPTER="$TMP/adapter"
ROUTER_POLICY_CONFIG="$TMP/config.json"
export BOOT_GUARD_CALL_LOG PROCD_CALL_LOG ROUTER_POLICY_ADAPTER
export ROUTER_POLICY_CONFIG

# shellcheck source=openwrt/init.d/router-policy-boot-guard
. "$ROOT/openwrt/init.d/router-policy-boot-guard"

start_service
grep -Fx "boot-guard $ROUTER_POLICY_CONFIG" "$BOOT_GUARD_CALL_LOG" >/dev/null
grep -Fx 'open:router-policy-boot-guard-lease' "$PROCD_CALL_LOG" >/dev/null
grep -F 'sleep 2147483647' "$PROCD_CALL_LOG" >/dev/null

stop_service
if grep -Fx "clear-boot-guard $ROUTER_POLICY_CONFIG" "$BOOT_GUARD_CALL_LOG" >/dev/null; then
  echo 'boot guard stop path cleared the forwarding fence' >&2
  exit 1
fi

echo "boot_guard_service_persistent_until_reconcile=true"
echo "boot_guard_stop_preserves_table=true"
