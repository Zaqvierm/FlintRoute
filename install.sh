#!/bin/sh
set -eu
umask 077

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
PREFIX="${PREFIX:-/usr/lib/router-policy}"
ETC_DIR="${ETC_DIR:-/etc/router-policy}"
STATE_DIR="${STATE_DIR:-/var/lib/router-policy}"
RUNTIME_DIR="${RUNTIME_DIR:-/tmp/router-policy}"
BACKUP_DIR="${BACKUP_DIR:-/root/router-policy-backup-$(date -u +%Y%m%dT%H%M%SZ)}"
BACKUP_SOURCES="${BACKUP_SOURCES:-/etc/config/network /etc/config/firewall /etc/config/dhcp /etc/dnsmasq.d /etc/nftables.d $ETC_DIR}"
TAR_BIN="${TAR_BIN:-tar}"

mode=""
enable_services=0

for arg in "$@"; do
  case "$arg" in
    --diagnose|--dry-run|--install|--test-apply|--activate|--rollback|--uninstall)
      mode="$arg"
      ;;
    --yes)
      :
      ;;
    --enable-services)
      enable_services=1
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

[ -n "$mode" ] || mode="--dry-run"

need_root_for_apply() {
  if [ "$(id -u)" != "0" ]; then
    echo "must run as root on OpenWrt for $mode" >&2
    exit 1
  fi
}

detect() {
  echo "== detect =="
  uname -a || true
  [ -f /etc/openwrt_release ] && cat /etc/openwrt_release || true
  command -v ubus >/dev/null 2>&1 && ubus call system board || true
  command -v fw4 >/dev/null 2>&1 && fw4 -V 2>/dev/null || true
  command -v nft >/dev/null 2>&1 && nft --version || true
  command -v dnsmasq >/dev/null 2>&1 && dnsmasq --version 2>&1 | head -n 5 || true
}

backup() {
  mkdir -p "$BACKUP_DIR"
  staging="$BACKUP_DIR/staging"
  archive="$BACKUP_DIR/config.tar"
  manifest="$BACKUP_DIR/manifest.txt"
  rm -rf "$staging"
  mkdir -p "$staging"
  : > "$manifest"
  backup_items=0
  for p in $BACKUP_SOURCES; do
    if [ -e "$p" ]; then
      relative="${p#/}"
      mkdir -p "$staging/$(dirname "$relative")"
      cp -R "$p" "$staging/$relative"
      echo "$p" >> "$manifest"
      backup_items=$((backup_items + 1))
    fi
  done
  [ "$backup_items" -gt 0 ] || { echo "backup has no source files" >&2; return 1; }
  "$TAR_BIN" -C "$staging" -cf "$archive.tmp" .
  mv "$archive.tmp" "$archive"
  [ -f "$archive" ] || { echo "backup archive was not created" >&2; return 1; }
  [ -s "$archive" ] || { echo "backup archive is empty" >&2; return 1; }
  "$TAR_BIN" -tf "$archive" >/dev/null
  archive_bytes="$(wc -c < "$archive" | tr -d ' ')"
  if command -v sha256sum >/dev/null 2>&1; then
    archive_hash="$(sha256sum "$archive" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    archive_hash="$(openssl dgst -sha256 "$archive" | awk '{print $NF}')"
  else
    echo "backup failed: neither sha256sum nor openssl is available" >&2
    return 1
  fi
  {
    echo "archive=config.tar"
    echo "bytes=$archive_bytes"
    echo "sha256=$archive_hash"
    echo "verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$manifest"
  rm -rf "$staging"
  echo "$BACKUP_DIR" > "$STATE_DIR/last-backup-path"
}

install_files() {
  mkdir -p "$PREFIX" "$ETC_DIR/config" "$ETC_DIR/secrets" "$ETC_DIR/xray" "$ETC_DIR/zapret" "$ETC_DIR/firewall" "$STATE_DIR/last-good" "$RUNTIME_DIR" /etc/init.d /etc/hotplug.d/iface /etc/hotplug.d/firewall /etc/dnsmasq.d
  cp -R "$ROOT/bin" "$PREFIX/"
  cp -R "$ROOT/scripts" "$PREFIX/"
  cp -R "$ROOT/openwrt" "$PREFIX/"
  if [ -f "$ROOT/dist/router-policy-linux-arm64" ]; then
    cp "$ROOT/dist/router-policy-linux-arm64" /usr/bin/router-policy
    chmod +x /usr/bin/router-policy
  else
    echo "missing dist/router-policy-linux-arm64; run scripts/build-go.sh before install" >&2
    exit 1
  fi
  if [ ! -f "$ETC_DIR/config/default.json" ]; then
    cp "$ROOT/config/default.json" "$ETC_DIR/config/default.json"
  else
    cp "$ROOT/config/default.json" "$ETC_DIR/config/factory-default.json"
  fi
  cp "$ROOT/config/schema.json" "$ETC_DIR/config/schema.json"
  if [ ! -f "$ETC_DIR/secrets/vpn-subscription-url" ]; then
    : > "$ETC_DIR/secrets/vpn-subscription-url"
  fi
  chmod 700 "$ETC_DIR/secrets"
  for secret in "$ETC_DIR/secrets/"*; do
    [ -e "$secret" ] && chmod 600 "$secret"
  done
  cp "$ROOT/openwrt/init.d/router-policy" /etc/init.d/router-policy
  cp "$ROOT/openwrt/init.d/router-policy-boot-guard" /etc/init.d/router-policy-boot-guard
  cp "$ROOT/openwrt/init.d/router-policy-watchdog" /etc/init.d/router-policy-watchdog
  cp "$ROOT/openwrt/init.d/router-policy-xray" /etc/init.d/router-policy-xray
  cp "$ROOT/openwrt/init.d/router-policy-zapret" /etc/init.d/router-policy-zapret
  cp "$ROOT/openwrt/hotplug/iface/95-router-policy" /etc/hotplug.d/iface/95-router-policy
  cp "$ROOT/openwrt/hotplug/firewall/95-router-policy" /etc/hotplug.d/firewall/95-router-policy
  chmod +x "$PREFIX/openwrt/adapter.sh" /etc/init.d/router-policy /etc/init.d/router-policy-boot-guard /etc/init.d/router-policy-watchdog /etc/init.d/router-policy-xray /etc/init.d/router-policy-zapret /etc/hotplug.d/iface/95-router-policy /etc/hotplug.d/firewall/95-router-policy /usr/bin/router-policy
}

dry_run() {
  detect
  echo "would_backup=$BACKUP_DIR"
  echo "would_install_prefix=$PREFIX"
  echo "would_install_config=$ETC_DIR/config/default.json"
  echo "would_install_services=router-policy-boot-guard router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
  echo "would_not_enable_services_without=--enable-services"
  echo "would_not_activate_without=--activate --yes"
}

if [ "${ROUTER_POLICY_INSTALL_LIB_ONLY:-0}" = "1" ]; then
  return 0
fi

case "$mode" in
  --diagnose)
    sh "$ROOT/scripts/diagnose-openwrt.sh"
    ;;
  --dry-run)
    dry_run
    ;;
  --install)
    need_root_for_apply
    mkdir -p "$STATE_DIR"
    detect
    backup
    install_files
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" /usr/bin/router-policy validate-config
    echo "== setup token =="
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" /usr/bin/router-policy auth setup-token
    if [ "$enable_services" = "1" ]; then
      /etc/init.d/router-policy-boot-guard enable
      /etc/init.d/router-policy enable
      /etc/init.d/router-policy-watchdog enable
      echo "services_enabled=router-policy-boot-guard router-policy router-policy-watchdog"
      echo "dataplane_services_boot_enabled=false"
    else
      echo "services_enabled=false"
      echo "enable_services_with=install.sh --install --enable-services"
    fi
    echo "installed=true"
    echo "activate_with=install.sh --activate --yes"
    ;;
  --test-apply)
    need_root_for_apply
    echo "test-apply requires a validated ChangeSet transaction; use the control-plane API" >&2
    exit 2
    ;;
  --activate)
    need_root_for_apply
    echo "activate requires a validated ChangeSet transaction; direct manual activation is disabled" >&2
    exit 2
    ;;
  --rollback)
    need_root_for_apply
    echo "rollback requires transaction ID, revision ID and rollback token; use the control-plane API" >&2
    exit 2
    ;;
  --uninstall)
    need_root_for_apply
    "$ROOT/uninstall.sh" --uninstall
    ;;
esac
