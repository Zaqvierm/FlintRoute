#!/bin/sh
set -eu
umask 077

PREFIX="${PREFIX:-/usr/lib/router-policy}"
ETC_DIR="${ETC_DIR:-/etc/router-policy}"
STATE_DIR="${STATE_DIR:-/var/lib/router-policy}"
BACKUP_DIR="${BACKUP_DIR:-/root/router-policy-uninstall-backup-$(date -u +%Y%m%dT%H%M%SZ)}"
mode="${1:---dry-run}"

if [ "$mode" = "--dry-run" ]; then
  echo "would_stop_services=router-policy-boot-guard router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
  echo "would_remove_prefix=$PREFIX"
  echo "would_keep_backup=$BACKUP_DIR"
  exit 0
fi

[ "$mode" = "--uninstall" ] || { echo "usage: uninstall.sh --dry-run|--uninstall" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }

mkdir -p "$BACKUP_DIR"
[ -d "$ETC_DIR" ] && tar -C / -cf "$BACKUP_DIR/router-policy-etc.tar" "${ETC_DIR#/}" 2>/dev/null || true
[ -d "$STATE_DIR" ] && tar -C / -cf "$BACKUP_DIR/router-policy-state.tar" "${STATE_DIR#/}" 2>/dev/null || true

/etc/init.d/router-policy stop 2>/dev/null || true
/etc/init.d/router-policy disable 2>/dev/null || true
/etc/init.d/router-policy-boot-guard stop 2>/dev/null || true
/etc/init.d/router-policy-boot-guard disable 2>/dev/null || true
/etc/init.d/router-policy-watchdog stop 2>/dev/null || true
/etc/init.d/router-policy-watchdog disable 2>/dev/null || true
/etc/init.d/router-policy-xray stop 2>/dev/null || true
/etc/init.d/router-policy-xray disable 2>/dev/null || true
/etc/init.d/router-policy-zapret stop 2>/dev/null || true
/etc/init.d/router-policy-zapret disable 2>/dev/null || true

rm -f /etc/init.d/router-policy /etc/init.d/router-policy-boot-guard /etc/init.d/router-policy-watchdog /etc/init.d/router-policy-xray /etc/init.d/router-policy-zapret
rm -f /etc/hotplug.d/iface/95-router-policy /etc/hotplug.d/firewall/95-router-policy
rm -f "$ETC_DIR/firewall/router-policy.nft" /etc/nftables.d/router-policy.nft /etc/dnsmasq.d/router-policy.conf
rm -f /usr/bin/router-policy
rm -rf "$PREFIX"

if command -v fw4 >/dev/null 2>&1; then
  fw4 reload || true
fi
if command -v nft >/dev/null 2>&1; then
  nft delete table inet router_policy >/dev/null 2>&1 || true
  nft delete table inet router_policy_boot_guard >/dev/null 2>&1 || true
fi
if [ -x /etc/init.d/dnsmasq ]; then
  /etc/init.d/dnsmasq restart || true
fi

echo "uninstalled=true"
echo "backup=$BACKUP_DIR"
