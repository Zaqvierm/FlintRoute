#!/bin/sh
set -eu

ROOT="$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

export ROUTER_POLICY_RUNTIME_DIR="$TMP/runtime"
export ROUTER_POLICY_HOTPLUG_EVENT="$ROOT/openwrt/hotplug-event"
for i in $(seq 1 100); do
  ACTION=ifupdate INTERFACE="lan$i" sh "$ROOT/openwrt/hotplug/iface/95-router-policy"
done

[ -f "$TMP/runtime/hotplug-events.log" ]
[ "$(wc -l < "$TMP/runtime/hotplug-events.log" | tr -d ' ')" -le 64 ]
grep -F "interface" "$TMP/runtime/hotplug-events.log" >/dev/null

if grep -F 'adapter.sh' "$ROOT/openwrt/hotplug/iface/95-router-policy" "$ROOT/openwrt/hotplug/firewall/95-router-policy" >/dev/null; then
  echo "hotplug still has direct adapter authority" >&2
  exit 1
fi
if grep -F 'fw4 reload' "$ROOT/openwrt/hotplug/iface/95-router-policy" "$ROOT/openwrt/hotplug/firewall/95-router-policy" >/dev/null; then
  echo "hotplug still has global firewall reload authority" >&2
  exit 1
fi

echo "hotplug_bounded_queue=true"
echo "hotplug_no_direct_mutation=true"
