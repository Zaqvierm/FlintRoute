#!/bin/sh
# The init script is sourced through a test-controlled absolute ROOT path.
# ShellCheck cannot resolve that runtime path in CI; the fixture owns the
# sourced file and exercises it explicitly below.
# shellcheck disable=SC1091
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-helper-service-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/etc/router-policy" "$TMP/run"

PROCD_LOG="$TMP/procd.log"
LOGGER_LOG="$TMP/logger.log"
export PROCD_LOG LOGGER_LOG

logger() { printf '%s\n' "$*" >> "$LOGGER_LOG"; }
chown() { printf '%s\n' "$*" >> "$TMP/chown.log"; }
procd_open_instance() { printf 'open:%s\n' "$*" >> "$PROCD_LOG"; }
procd_set_param() { printf 'param:%s\n' "$*" >> "$PROCD_LOG"; }
procd_close_instance() { printf 'close\n' >> "$PROCD_LOG"; }

ROUTER_POLICY_HELPER_ENV="$TMP/etc/router-policy/helper.env"
ROUTER_POLICY_HELPER_RUN_DIR="$TMP/run"
export ROUTER_POLICY_HELPER_ENV
export ROUTER_POLICY_HELPER_RUN_DIR
# shellcheck source=openwrt/init.d/router-policy-helper
. "$ROOT/openwrt/init.d/router-policy-helper"

start_service
grep -F 'disabled: explicit non-root peer_uid is required' "$LOGGER_LOG" >/dev/null
[ ! -s "$PROCD_LOG" ]

printf 'peer_uid=0\nsocket=/var/run/router-policy/helper.sock\n' > "$ROUTER_POLICY_HELPER_ENV"
start_service
grep -F 'disabled: helper.env peer_uid is invalid' "$LOGGER_LOG" >/dev/null
[ ! -e "$PROCD_LOG" ] || [ "$(grep -c '^open:' "$PROCD_LOG")" -eq 0 ]

printf 'peer_uid=1001\nsocket=/var/run/router-policy/helper.sock\n' > "$ROUTER_POLICY_HELPER_ENV"
start_service
grep -F 'open:router-policy-helper' "$PROCD_LOG" >/dev/null
env_line=$(grep '^param:env ' "$PROCD_LOG" | tail -n 1)
printf '%s\n' "$env_line" | grep -F 'ROUTER_POLICY_HELPER_PEER_UID=1001' >/dev/null
printf '%s\n' "$env_line" | grep -F 'ROUTER_POLICY_HELPER_SOCKET=/var/run/router-policy/helper.sock' >/dev/null
printf '%s\n' "$env_line" | grep -F 'ROUTER_POLICY_ADAPTER_PATH=/usr/lib/router-policy/openwrt/adapter.sh' >/dev/null
printf '%s\n' "$env_line" | grep -F 'ROUTER_POLICY_CONFIG_PATH=/etc/router-policy/config/default.json' >/dev/null
printf '%s\n' "$env_line" | grep -F 'ROUTER_POLICY_INIT_DIR=/etc/init.d' >/dev/null
[ "$(grep -c '^param:env ' "$PROCD_LOG")" -eq 1 ] || {
  echo "helper environment was split across replace-style procd calls" >&2
  exit 1
}
grep -F 'param:command /usr/bin/router-policy-helper' "$PROCD_LOG" >/dev/null
grep -F "0:1001 $TMP/run" "$TMP/chown.log" >/dev/null
if grep -F 'param:env' "$PROCD_LOG" | tail -n 1 | grep -F 'ROUTER_POLICY_HELPER_PEER_UID=1001' >/dev/null; then
  :
else
  echo "helper peer environment missing after runtime directory setup" >&2
  exit 1
fi

printf 'peer_uid=1001\nsocket=/tmp/unsafe.sock\n' > "$ROUTER_POLICY_HELPER_ENV"
start_service
grep -F 'disabled: helper socket path is not allowlisted' "$LOGGER_LOG" >/dev/null

echo "helper_service_requires_explicit_peer=true"
echo "helper_service_uses_fixed_socket=true"
