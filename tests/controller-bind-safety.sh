#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
INIT="$ROOT/openwrt/init.d/router-policy"

# The controller is still root in v1.  Its binary rejects non-loopback binds,
# and the init script must not export the legacy escape hatch that bypasses
# that check.  Keep this as a regression guard until the non-root split is
# production-complete.
if grep -v '^[[:space:]]*#' "$INIT" | grep -F 'ROUTER_POLICY_ALLOW_FIREWALLED_BIND' >/dev/null; then
  echo "root controller init still exposes the firewalled-bind escape hatch" >&2
  exit 1
fi
if grep -Eq 'procd_append_param[[:space:]]+env[[:space:]]+ROUTER_POLICY_ALLOW_FIREWALLED_BIND' "$INIT"; then
  echo "root controller init exports a non-loopback bind override" >&2
  exit 1
fi
grep -F 'listen_address=127.0.0.1:8787' "$INIT" >/dev/null

echo "controller_bind_safety=loopback_only_while_root"
