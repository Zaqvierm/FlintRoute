#!/bin/sh
set -eu

if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then
  printf '%s\n' 'NOT RUN LOCALLY — requires Linux network namespace/nftables'
  exit 0
fi
if [ "$(id -u)" -ne 0 ] || ! command -v ip >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1 || ! command -v ping >/dev/null 2>&1; then
  printf '%s\n' 'NOT RUN LOCALLY — requires root, iproute2, nftables and ping'
  exit 0
fi

suffix="$$"
client="rp-bg-client-$suffix"
router="rp-bg-router-$suffix"
server="rp-bg-server-$suffix"
foreign_batch="$(mktemp)"
owned_batch="$(mktemp)"
guard_only="$(mktemp)"
traffic_pid=""
cleanup() {
  if [ -n "$traffic_pid" ]; then
    kill "$traffic_pid" 2>/dev/null || true
    wait "$traffic_pid" 2>/dev/null || true
  fi
  ip netns del "$client" 2>/dev/null || true
  ip netns del "$router" 2>/dev/null || true
  ip netns del "$server" 2>/dev/null || true
  rm -f "$foreign_batch" "$owned_batch" "$guard_only"
}
trap cleanup EXIT HUP INT TERM

ip netns add "$client"
ip netns add "$router"
ip netns add "$server"
ip link add "rp-c-$suffix" type veth peer name "rp-r0-$suffix"
ip link set "rp-c-$suffix" netns "$client"
ip link set "rp-r0-$suffix" netns "$router"
ip link add "rp-s-$suffix" type veth peer name "rp-r1-$suffix"
ip link set "rp-s-$suffix" netns "$server"
ip link set "rp-r1-$suffix" netns "$router"

ip netns exec "$client" ip link set lo up
ip netns exec "$client" ip link set "rp-c-$suffix" name lan0 up
ip netns exec "$client" ip addr add 198.18.0.2/24 dev lan0
ip netns exec "$client" ip route add default via 198.18.0.1

ip netns exec "$router" ip link set lo up
ip netns exec "$router" ip link set "rp-r0-$suffix" name lan0 up
ip netns exec "$router" ip link set "rp-r1-$suffix" name wan0 up
ip netns exec "$router" ip addr add 198.18.0.1/24 dev lan0
ip netns exec "$router" ip addr add 198.18.1.1/24 dev wan0
ip netns exec "$router" sysctl -q -w net.ipv4.ip_forward=1

ip netns exec "$server" ip link set lo up
ip netns exec "$server" ip link set "rp-s-$suffix" name wan0 up
ip netns exec "$server" ip addr add 198.18.1.2/24 dev wan0
ip netns exec "$server" ip addr add 198.18.1.3/24 dev wan0
ip netns exec "$server" ip route add default via 198.18.1.1

run_nft() {
  ip netns exec "$router" nft "$@"
}

cat >"$foreign_batch" <<'NFT'
table inet foreign {
  chain forward {
    type filter hook forward priority -200; policy accept;
    ip daddr { 198.18.1.2, 198.18.1.3 } meta mark != 0x110 counter comment "foreign-direct-escape"
  }
}
NFT

cat >"$owned_batch" <<'NFT'
table inet router_policy {
  set protected_v4 {
    type ipv4_addr
    elements = { 198.18.1.2, 198.18.1.3 }
  }
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "lan0" ip daddr @protected_v4 meta mark set 0x110 ct mark set 0x110 counter comment "verified-committed-classifier"
  }
}
table inet router_policy_boot_guard {
  chain forward {
    type filter hook forward priority -300; policy drop;
    meta mark 0x110 counter accept comment "rp boot_guard allow=verified-classifier"
    ct mark 0x110 counter accept comment "rp boot_guard allow=verified-conntrack"
    counter drop comment "rp boot_guard action=drop-unclassified"
  }
}
NFT

cat >"$guard_only" <<'NFT'
table inet router_policy_boot_guard {
  chain forward {
    type filter hook forward priority -300; policy drop;
    counter drop comment "rp boot_guard action=drop-unclassified"
  }
}
NFT

# The foreign table exists independently and is deliberately not included in
# the owned transition.  The committed classifier and guard are loaded in one
# transaction before any forwarding assertion.
run_nft -f "$foreign_batch"
run_nft -f "$owned_batch"
foreign_before="$(run_nft list table inet foreign)"

if ! ip netns exec "$client" ping -c 3 -W 1 198.18.1.2 >/dev/null 2>&1; then
  echo 'protected traffic failed with verified early classifier' >&2
  exit 1
fi

drop_target="$(run_nft list chain inet router_policy_boot_guard forward | awk '/drop-unclassified/ {for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i + 1); exit}}')"
case "$drop_target" in ''|*[!0-9]*) echo 'boot guard drop counter missing' >&2; exit 1 ;; esac
[ "$drop_target" -eq 0 ] || { echo "protected traffic hit unclassified drop: $drop_target" >&2; exit 1; }
classifier_packets="$(run_nft list chain inet router_policy prerouting | awk '/verified-committed-classifier/ {for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i + 1); exit}}')"
case "$classifier_packets" in ''|*[!0-9]*) echo 'classifier counter missing' >&2; exit 1 ;; esac
[ "$classifier_packets" -gt 0 ] || { echo 'classifier did not see protected traffic' >&2; exit 1; }
foreign_after="$(run_nft list table inet foreign)"
[ "$foreign_after" = "$foreign_before" ] || { echo 'foreign table changed during boot fence test' >&2; exit 1; }
foreign_packets="$(run_nft list chain inet foreign forward | awk '/foreign-direct-escape/ {for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i + 1); exit}}')"
case "$foreign_packets" in 0|'') ;; *) echo "protected traffic reached foreign hook: $foreign_packets" >&2; exit 1 ;; esac

# A new/unmarked flow is fail-closed while the classifier is absent.  This
# models an empty conntrack table immediately after reboot.
run_nft delete table inet router_policy
run_nft delete table inet router_policy_boot_guard
run_nft -f "$guard_only"
if ip netns exec "$client" ping -c 1 -W 1 198.18.1.3 >/dev/null 2>&1; then
  echo 'unmarked traffic escaped guard while classifier was absent' >&2
  exit 1
fi
guard_only_packets="$(run_nft list chain inet router_policy_boot_guard forward | awk '/drop-unclassified/ {for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i + 1); exit}}')"
case "$guard_only_packets" in ''|*[!0-9]*) echo 'guard-only drop counter missing' >&2; exit 1 ;; esac
[ "$guard_only_packets" -gt 0 ] || { echo 'guard-only DROP did not see unmarked flow' >&2; exit 1; }

# Simulated reboot/reconcile: restore the exact committed classifier and guard
# in one batch, then prove the protected path works again.
run_nft delete table inet router_policy_boot_guard
run_nft -f "$owned_batch"
ip netns exec "$client" ping -c 2 -W 1 198.18.1.2 >/dev/null 2>&1 || {
  echo 'protected traffic failed after simulated reboot restore' >&2
  exit 1
}

printf '%s\n' 'boot_guard_namespace_ok=true'
