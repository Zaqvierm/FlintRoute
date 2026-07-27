#!/bin/sh
set -eu
umask 077

SYSTEM_ROOT="${ROUTER_POLICY_SYSTEM_ROOT:-}"
PREFIX="${PREFIX:-$SYSTEM_ROOT/usr/lib/router-policy}"
ETC_DIR="${ETC_DIR:-$SYSTEM_ROOT/etc/router-policy}"
STATE_DIR="${STATE_DIR:-$ETC_DIR/state}"
BIN_DIR="${BIN_DIR:-$SYSTEM_ROOT/usr/bin}"
INIT_DIR="${INIT_DIR:-$SYSTEM_ROOT/etc/init.d}"
HOTPLUG_IFACE_DIR="${HOTPLUG_IFACE_DIR:-$SYSTEM_ROOT/etc/hotplug.d/iface}"
HOTPLUG_FIREWALL_DIR="${HOTPLUG_FIREWALL_DIR:-$SYSTEM_ROOT/etc/hotplug.d/firewall}"
DNSMASQ_DIR="${DNSMASQ_DIR:-$SYSTEM_ROOT/etc/dnsmasq.d}"
NFTABLES_DIR="${NFTABLES_DIR:-$SYSTEM_ROOT/etc/nftables.d}"
BACKUP_ROOT="${BACKUP_ROOT:-$SYSTEM_ROOT/root/router-policy-backups}"
BACKUP_DIR="${BACKUP_DIR:-$BACKUP_ROOT/uninstall-$(date -u +%Y%m%dT%H%M%SZ)}"
ROUTER_POLICY_VERSION="${ROUTER_POLICY_VERSION:-unknown}"
TAR_BIN="${TAR_BIN:-tar}"
SERVICES="router-policy-boot-guard router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
mode="${1:---dry-run}"

if [ "$mode" = "--dry-run" ]; then
  echo "would_stop_services=router-policy-boot-guard router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
  echo "would_remove_prefix=$PREFIX"
  echo "would_keep_backup=$BACKUP_DIR"
  exit 0
fi

[ "$mode" = "--uninstall" ] || { echo "usage: uninstall.sh --dry-run|--uninstall" >&2; exit 2; }
[ -n "$SYSTEM_ROOT" ] || [ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }

if [ -z "$SYSTEM_ROOT" ] && [ -x "$BIN_DIR/router-policy" ]; then
  ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$BIN_DIR/router-policy" maintenance begin --owner "installer:uninstall-$$" --reason uninstall --lease 30m >/dev/null
fi

mkdir -p "$BACKUP_DIR"
manifest="$BACKUP_DIR/manifest.txt"
archive="$BACKUP_DIR/router-policy-etc.tar"
: > "$manifest"
if [ -d "$ETC_DIR" ]; then
  "$TAR_BIN" -C / -cf "$archive.tmp" "${ETC_DIR#/}"
  mv "$archive.tmp" "$archive"
  [ -s "$archive" ] || { echo "uninstall backup is empty" >&2; exit 1; }
  "$TAR_BIN" -tf "$archive" >/dev/null
  if command -v sha256sum >/dev/null 2>&1; then
    archive_hash="$(sha256sum "$archive" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    archive_hash="$(openssl dgst -sha256 "$archive" | awk '{print $NF}')"
  else
    echo "uninstall backup failed: neither sha256sum nor openssl is available" >&2
    exit 1
  fi
  {
    echo "config=router-policy-etc.tar"
    echo "sha256=$archive_hash"
    echo "state_dir=$STATE_DIR"
  } >> "$manifest"
else
  echo "config=absent" >> "$manifest"
fi
echo "verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$manifest"

if [ -x "$BIN_DIR/router-policy" ]; then
  "$BIN_DIR/router-policy" backup register --root "$BACKUP_DIR" --operation "$(basename "$BACKUP_DIR")" --version "$ROUTER_POLICY_VERSION" --reason uninstall --retention-class uninstall-fallback >/dev/null
  "$BIN_DIR/router-policy" backup prune --root "$BACKUP_ROOT" --max 2 --max-bytes 134217728 --apply >/dev/null
fi

if [ -z "$SYSTEM_ROOT" ]; then
  for service in $SERVICES; do
    init="$INIT_DIR/$service"
    [ -x "$init" ] && "$init" stop 2>/dev/null || true
    [ -x "$init" ] && "$init" disable 2>/dev/null || true
  done
fi

rm -f "$INIT_DIR/router-policy" "$INIT_DIR/router-policy-boot-guard" "$INIT_DIR/router-policy-watchdog" "$INIT_DIR/router-policy-xray" "$INIT_DIR/router-policy-zapret"
rm -f "$HOTPLUG_IFACE_DIR/95-router-policy" "$HOTPLUG_FIREWALL_DIR/95-router-policy"
rm -f "$ETC_DIR/firewall/router-policy.nft" "$NFTABLES_DIR/router-policy.nft" "$DNSMASQ_DIR/router-policy.conf"
rm -f "$BIN_DIR/router-policy"
rm -rf "$PREFIX"
rm -f "$SYSTEM_ROOT/tmp/router-policy/watchdog-inhibit.json"

if [ -z "$SYSTEM_ROOT" ] && command -v fw4 >/dev/null 2>&1; then
  fw4 reload || true
fi
if [ -z "$SYSTEM_ROOT" ] && command -v nft >/dev/null 2>&1; then
  nft delete table inet router_policy >/dev/null 2>&1 || true
  nft delete table inet router_policy_boot_guard >/dev/null 2>&1 || true
fi
if [ -z "$SYSTEM_ROOT" ] && [ -x "$INIT_DIR/dnsmasq" ]; then
  "$INIT_DIR/dnsmasq" restart || true
fi

echo "uninstalled=true"
echo "backup=$BACKUP_DIR"
