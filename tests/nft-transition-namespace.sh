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

ns="router-policy-nft-$$"
batch="$(mktemp)"
old="$(mktemp)"
new="$(mktemp)"
bad="$(mktemp)"
traffic_pid=""
cleanup() {
  if [ -n "$traffic_pid" ]; then
    kill "$traffic_pid" 2>/dev/null || true
    wait "$traffic_pid" 2>/dev/null || true
  fi
  ip netns del "$ns" 2>/dev/null || true
  rm -f "$batch" "$old" "$new" "$bad"
}
trap cleanup EXIT HUP INT TERM

ip netns add "$ns"
ip netns exec "$ns" ip link set lo up

cat >"$old" <<'NFT'
table inet foreign {
  chain output {
    type filter hook output priority -200; policy accept;
    counter comment "foreign-must-survive"
  }
}
table inet router_policy {
  chain output {
    type filter hook output priority -300; policy accept;
    ip daddr 127.0.0.1 counter drop comment "protected-drop"
  }
}
NFT

cat >"$new" <<'NFT'
table inet foreign {
  chain output {
    type filter hook output priority -200; policy accept;
    counter comment "foreign-must-survive"
  }
}
table inet router_policy {
  chain output {
    type filter hook output priority -300; policy accept;
    ip daddr 127.0.0.1 counter drop comment "protected-drop-generation-2"
  }
}
NFT

cat >"$bad" <<'NFT'
table inet router_policy {
  chain output {
    type filter hook output priority -300; policy accept;
    this is intentionally invalid
  }
}
NFT

run_nft() {
  ip netns exec "$ns" nft "$@"
}

run_nft -f "$old"
traffic_pid="$(ip netns exec "$ns" sh -c 'while :; do ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true; done' >/dev/null 2>&1 & echo $!)"
sleep 1

{
  printf '%s\n' 'delete table inet router_policy'
  cat "$new"
} >"$batch"
run_nft -c -f "$batch"
run_nft -f "$batch"

if run_nft -c -f "$bad" >/dev/null 2>&1; then
  echo 'invalid nft batch unexpectedly passed syntax check' >&2
  exit 1
fi
run_nft list table inet router_policy >/dev/null
run_nft list table inet foreign >/dev/null

drop_packets="$(run_nft list chain inet router_policy output | awk '/protected-drop-generation-2/ {for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i + 1); exit}}')"
case "$drop_packets" in
  ''|*[!0-9]*)
    echo 'protected drop counter is missing after atomic transition' >&2
    exit 1
    ;;
esac
[ "$drop_packets" -gt 0 ] || {
  echo 'protected drop rule disappeared after atomic transition' >&2
  exit 1
}
foreign_counter="$(run_nft list chain inet foreign output | awk '/counter packets/ {print $3; exit}')"
case "$foreign_counter" in
  0|"" ) ;;
  * )
    echo "protected traffic reached foreign/direct chain: packets=$foreign_counter" >&2
    exit 1
    ;;
esac

run_nft delete table inet router_policy
if run_nft list table inet router_policy >/dev/null 2>&1; then
  echo 'owned nft table survived cleanup' >&2
  exit 1
fi
run_nft list table inet foreign >/dev/null
printf '%s\n' 'nft_transition_namespace_ok=true'
