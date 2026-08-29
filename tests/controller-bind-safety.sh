#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
INIT="$ROOT/openwrt/init.d/router-policy"
INSTALL="$ROOT/install.sh"

# The controller runs as the non-root daemon account and uses only the fixed
# root-helper socket for privileged operations. The default remains
# loopback-only; LAN exposure is still an explicit private-address opt-in.
if grep -v '^[[:space:]]*#' "$INIT" | grep -F 'ROUTER_POLICY_ALLOW_FIREWALLED_BIND' >/dev/null; then
  echo "root controller init still exposes the broad firewalled-bind escape hatch" >&2
  exit 1
fi
if ! grep -Eq 'ROUTER_POLICY_ALLOW_LAN_BIND=1' "$INIT"; then
  echo "root controller init has no explicit private-LAN bind path" >&2
  exit 1
fi
if ! grep -Eq 'procd_set_param env ROUTER_POLICY_CONFIG=/etc/router-policy/config/default\.json ROUTER_POLICY_ALLOW_LAN_BIND=1' "$INIT"; then
  echo "LAN opt-in must preserve the absolute config environment" >&2
  exit 1
fi
grep -F 'listen_address=127.0.0.1:8787' "$INIT" >/dev/null
grep -F 'allow_lan_bind=0' "$INIT" >/dev/null
grep -F 'procd_set_param user daemon' "$INIT" >/dev/null
grep -F 'ROUTER_POLICY_HELPER_SOCKET=/var/run/router-policy/helper.sock' "$INIT" >/dev/null

# A clean --enable-services install must bring up the privileged executor
# before the non-root controller.  Merely shipping/enabling the helper is not
# enough: starting router-policy first produces a deterministic health failure
# because its fixed Unix socket does not exist yet.
grep -F "run_bounded \"\$INIT_DIR/router-policy-helper\" enable" "$INSTALL" >/dev/null
start_block=$(awk '/^start_control_services\(\)/,/^}/' "$INSTALL")
helper_line=$(printf '%s\n' "$start_block" | grep -n 'for service in router-policy-helper router-policy router-policy-watchdog' | cut -d: -f1)
[ -n "$helper_line" ] || {
  echo "controller start order does not declare helper dependency" >&2
  exit 1
}
grep -F 'for service in router-policy-watchdog router-policy router-policy-helper' "$INSTALL" >/dev/null
grep -F 'controller was running without its helper service' "$INSTALL" >/dev/null

echo "controller_bind_safety=loopback_default_private_lan_opt_in"
echo "controller_helper_dependency=enabled_and_started_before_controller"
