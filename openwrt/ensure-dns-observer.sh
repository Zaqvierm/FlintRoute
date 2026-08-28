#!/bin/sh
set -eu
umask 077

bootstrap="${ROUTER_POLICY_DNS_OBSERVER_BOOTSTRAP:-/usr/lib/router-policy/openwrt/dnsmasq/router-policy.conf}"
confdir="${ROUTER_POLICY_DNSMASQ_CONFDIR:-$(uci -q get 'dhcp.@dnsmasq[0].confdir' 2>/dev/null || true)}"
system_root="${ROUTER_POLICY_SYSTEM_ROOT:-}"
dnsmasq_init="${DNSMASQ_INIT:-/etc/init.d/dnsmasq}"
dnsmasq_bin="${DNSMASQ_BIN:-dnsmasq}"
nslookup_bin="${NSLOOKUP_BIN:-nslookup}"
sleep_bin="${SLEEP_BIN:-sleep}"
reload_if_needed=0

case "${1:-}" in
  "") ;;
  --reload-if-needed) reload_if_needed=1 ;;
  *)
    echo "usage: ensure-dns-observer.sh [--reload-if-needed]" >&2
    exit 2
    ;;
esac

validate_no_symlink_path() {
  candidate="$1"
  case "$candidate" in
    /*) ;;
    *) return 1 ;;
  esac
  [ "$candidate" != "/" ] || return 1
  remainder=${candidate#/}
  current=""
  while [ -n "$remainder" ]; do
    case "$remainder" in
      */*) component=${remainder%%/*}; remainder=${remainder#*/} ;;
      *) component=$remainder; remainder= ;;
    esac
    case "$component" in
      ""|.|..) return 1 ;;
    esac
    current="$current/$component"
    [ ! -L "$current" ] || return 1
  done
}

[ -n "$confdir" ] || {
  echo "dns_observer=skipped"
  echo "reason=dnsmasq_confdir_unknown"
  exit 0
}
[ "$confdir" = "$system_root/tmp/dnsmasq.d" ] ||
  [ "$confdir" = "$system_root/etc/dnsmasq.d" ] || {
  echo "dns_observer=error" >&2
  echo "reason=dnsmasq_confdir_unowned" >&2
  exit 1
}
validate_no_symlink_path "$confdir" || {
  echo "dns_observer=error" >&2
  echo "reason=dnsmasq_confdir_symlink" >&2
  exit 1
}
[ -f "$bootstrap" ] && [ ! -L "$bootstrap" ] || {
  echo "dns_observer=error" >&2
  echo "reason=bootstrap_not_regular" >&2
  exit 1
}
[ ! -L "$confdir" ] || {
  echo "dns_observer=error" >&2
  echo "reason=dnsmasq_confdir_symlink" >&2
  exit 1
}

mkdir -p "$confdir"
target="$confdir/router-policy.conf"
[ ! -L "$target" ] || {
  echo "dns_observer=error" >&2
  echo "reason=target_symlink" >&2
  exit 1
}

if [ -f "$target" ]; then
  echo "dns_observer=present"
  if [ "$reload_if_needed" = 1 ] && [ -x "$dnsmasq_init" ] && "$dnsmasq_init" running >/dev/null 2>&1; then
    "$dnsmasq_init" restart
    attempt=0
    max_attempts="${ROUTER_POLICY_DNSMASQ_READY_ATTEMPTS:-30}"
    while [ "$attempt" -lt "$max_attempts" ]; do
      if "$dnsmasq_init" running >/dev/null 2>&1 &&
        "$nslookup_bin" localhost 127.0.0.1 >/dev/null 2>&1; then
        echo "dnsmasq_restart=performed"
        break
      fi
      attempt=$((attempt + 1))
      "$sleep_bin" 1
    done
    [ "$attempt" -lt "$max_attempts" ] || {
      echo "dns_observer=error" >&2
      echo "reason=dnsmasq_not_ready_after_restart" >&2
      exit 1
    }
  else
    echo "dnsmasq_restart=not-needed"
  fi
  exit 0
fi

temporary="$(mktemp "$target.bootstrap.XXXXXX")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cp "$bootstrap" "$temporary"
chmod 644 "$temporary"
"$dnsmasq_bin" --test --conf-file="$temporary" >/dev/null
mv "$temporary" "$target"
trap - EXIT HUP INT TERM

if [ "$reload_if_needed" = 1 ] && [ -x "$dnsmasq_init" ] && "$dnsmasq_init" running >/dev/null 2>&1; then
  "$dnsmasq_init" restart
  attempt=0
  max_attempts="${ROUTER_POLICY_DNSMASQ_READY_ATTEMPTS:-30}"
  while [ "$attempt" -lt "$max_attempts" ]; do
    if "$dnsmasq_init" running >/dev/null 2>&1 &&
      "$nslookup_bin" localhost 127.0.0.1 >/dev/null 2>&1; then
      echo "dnsmasq_restart=performed"
      break
    fi
    attempt=$((attempt + 1))
    "$sleep_bin" 1
  done
  [ "$attempt" -lt "$max_attempts" ] || {
    echo "dns_observer=error" >&2
    echo "reason=dnsmasq_not_ready_after_restart" >&2
    exit 1
  }
else
  echo "dnsmasq_restart=not-requested"
fi

echo "dns_observer=installed"
echo "path=$target"
