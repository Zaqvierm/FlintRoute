#!/bin/sh
set -eu

ROOT=$(cd -- "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/openwrt/ensure-dns-observer.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/bin" "$TMP/root/tmp/dnsmasq.d"

cat > "$TMP/bin/dnsmasq" <<'EOF'
#!/bin/sh
[ "${1:-}" = "--test" ]
exit 0
EOF
cat > "$TMP/bin/dnsmasq-init" <<'EOF'
#!/bin/sh
case "${1:-}" in
  running) exit 0 ;;
  restart) printf 'restart\n' >> "$DNSMASQ_RESTART_LOG"; exit 0 ;;
esac
exit 1
EOF
cat > "$TMP/bin/nslookup" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$TMP/bin/sleep" <<'EOF'
#!/bin/sh
:
EOF
cat > "$TMP/bin/uci" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TMP/bin/dnsmasq" "$TMP/bin/dnsmasq-init" "$TMP/bin/nslookup" "$TMP/bin/sleep" "$TMP/bin/uci"

export PATH="$TMP/bin:$PATH"
export DNSMASQ_BIN="$TMP/bin/dnsmasq"
export DNSMASQ_INIT="$TMP/bin/dnsmasq-init"
export NSLOOKUP_BIN="$TMP/bin/nslookup"
export SLEEP_BIN="$TMP/bin/sleep"
export DNSMASQ_RESTART_LOG="$TMP/restarts.log"
export ROUTER_POLICY_DNS_OBSERVER_BOOTSTRAP="$ROOT/openwrt/dnsmasq/router-policy.conf"
export ROUTER_POLICY_SYSTEM_ROOT="$TMP/root"
export ROUTER_POLICY_DNSMASQ_CONFDIR="$TMP/root/tmp/dnsmasq.d"

first=$(sh "$SCRIPT")
printf '%s\n' "$first" | grep -Fx 'dns_observer=installed' >/dev/null
printf '%s\n' "$first" | grep -Fx 'dnsmasq_restart=not-requested' >/dev/null
cmp "$ROUTER_POLICY_DNS_OBSERVER_BOOTSTRAP" "$TMP/root/tmp/dnsmasq.d/router-policy.conf"

if [ -e "$DNSMASQ_RESTART_LOG" ]; then
  echo "boot-safe bootstrap restarted dnsmasq" >&2
  exit 1
fi

second=$(sh "$SCRIPT")
printf '%s\n' "$second" | grep -Fx 'dns_observer=present' >/dev/null
[ ! -e "$DNSMASQ_RESTART_LOG" ]

existing_reload=$(sh "$SCRIPT" --reload-if-needed)
printf '%s\n' "$existing_reload" | grep -Fx 'dns_observer=present' >/dev/null
printf '%s\n' "$existing_reload" | grep -Fx 'dnsmasq_restart=performed' >/dev/null
[ "$(wc -l < "$DNSMASQ_RESTART_LOG" | tr -d ' ')" -eq 1 ]

printf 'server=/managed.example/1.1.1.1\n' > "$TMP/root/tmp/dnsmasq.d/router-policy.conf"
sh "$SCRIPT" >/dev/null
grep -Fx 'server=/managed.example/1.1.1.1' "$TMP/root/tmp/dnsmasq.d/router-policy.conf" >/dev/null
[ "$(wc -l < "$DNSMASQ_RESTART_LOG" | tr -d ' ')" -eq 1 ]

mkdir "$TMP/root/etc" "$TMP/root/etc/dnsmasq.d"
live=$(ROUTER_POLICY_DNSMASQ_CONFDIR="$TMP/root/etc/dnsmasq.d" sh "$SCRIPT" --reload-if-needed)
printf '%s\n' "$live" | grep -Fx 'dnsmasq_restart=performed' >/dev/null
[ "$(wc -l < "$DNSMASQ_RESTART_LOG" | tr -d ' ')" -eq 2 ]

grep -Eq '^START=18$' "$ROOT/openwrt/init.d/router-policy-dns-observer"
if grep -F 'ensure-dns-observer.sh' "$ROOT/openwrt/init.d/router-policy" >/dev/null; then
  echo "controller still performs late DNS bootstrap" >&2
  exit 1
fi

mkdir "$TMP/root/tmp/dnsmasq-symlink"
if ln -s "$TMP/foreign" "$TMP/root/tmp/dnsmasq-symlink/router-policy.conf" 2>/dev/null; then
  set +e
  symlink_output=$(ROUTER_POLICY_DNSMASQ_CONFDIR="$TMP/root/tmp/dnsmasq-symlink" sh "$SCRIPT" 2>&1)
  symlink_rc=$?
  set -e
  [ "$symlink_rc" -ne 0 ]
  printf '%s\n' "$symlink_output" | grep -Fx 'reason=target_symlink' >/dev/null
else
  echo "symlink_test=skipped-filesystem"
fi

set +e
unowned_output=$(ROUTER_POLICY_DNSMASQ_CONFDIR="$TMP/root/etc/shadow" sh "$SCRIPT" 2>&1)
unowned_rc=$?
set -e
[ "$unowned_rc" -ne 0 ]
printf '%s\n' "$unowned_output" | grep -Fx 'reason=dnsmasq_confdir_unowned' >/dev/null

unset ROUTER_POLICY_DNSMASQ_CONFDIR
unknown=$(sh "$SCRIPT")
printf '%s\n' "$unknown" | grep -Fx 'reason=dnsmasq_confdir_unknown' >/dev/null

echo "dns_observer_bootstrap_ok=true"
