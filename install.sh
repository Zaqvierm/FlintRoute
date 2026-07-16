#!/bin/sh
set -eu
umask 077

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
SYSTEM_ROOT="${ROUTER_POLICY_SYSTEM_ROOT:-}"
PREFIX="${PREFIX:-$SYSTEM_ROOT/usr/lib/router-policy}"
ETC_DIR="${ETC_DIR:-$SYSTEM_ROOT/etc/router-policy}"
STATE_DIR="${STATE_DIR:-$ETC_DIR/state}"
RUNTIME_DIR="${RUNTIME_DIR:-$SYSTEM_ROOT/tmp/router-policy}"
BIN_DIR="${BIN_DIR:-$SYSTEM_ROOT/usr/bin}"
INIT_DIR="${INIT_DIR:-$SYSTEM_ROOT/etc/init.d}"
RC_DIR="${RC_DIR:-$SYSTEM_ROOT/etc/rc.d}"
HOTPLUG_IFACE_DIR="${HOTPLUG_IFACE_DIR:-$SYSTEM_ROOT/etc/hotplug.d/iface}"
HOTPLUG_FIREWALL_DIR="${HOTPLUG_FIREWALL_DIR:-$SYSTEM_ROOT/etc/hotplug.d/firewall}"
DNSMASQ_DIR="${DNSMASQ_DIR:-$SYSTEM_ROOT/etc/dnsmasq.d}"
ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-$BIN_DIR/router-policy}"
SOURCE_BINARY="${SOURCE_BINARY:-$ROOT/dist/router-policy-linux-arm64}"
BACKUP_DIR="${BACKUP_DIR:-$SYSTEM_ROOT/root/router-policy-backup-$(date -u +%Y%m%dT%H%M%SZ)}"
BACKUP_SOURCES="${BACKUP_SOURCES:-$SYSTEM_ROOT/etc/config/network $SYSTEM_ROOT/etc/config/firewall $SYSTEM_ROOT/etc/config/dhcp $SYSTEM_ROOT/etc/dnsmasq.d $SYSTEM_ROOT/etc/nftables.d $ETC_DIR}"
TAR_BIN="${TAR_BIN:-tar}"
SERVICES="router-policy-boot-guard router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
INSTALL_TARGETS="$PREFIX $ROUTER_POLICY_BIN $INIT_DIR/router-policy $INIT_DIR/router-policy-boot-guard $INIT_DIR/router-policy-watchdog $INIT_DIR/router-policy-xray $INIT_DIR/router-policy-zapret $HOTPLUG_IFACE_DIR/95-router-policy $HOTPLUG_FIREWALL_DIR/95-router-policy $ETC_DIR/config/default.json $ETC_DIR/config/factory-default.json $ETC_DIR/config/schema.json $ETC_DIR/secrets/vpn-subscription-url $STATE_DIR/last-backup-path $STATE_DIR/auth/setup-token.json"

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
  if [ -z "$SYSTEM_ROOT" ] && [ "$(id -u)" != "0" ]; then
    echo "must run as root on OpenWrt for $mode" >&2
    exit 1
  fi
}

preflight_install() {
  [ -f "$SOURCE_BINARY" ] || { echo "missing $SOURCE_BINARY; run scripts/build-go.sh before install" >&2; return 1; }
  for p in "$ROOT/scripts" "$ROOT/openwrt" "$ROOT/config/default.json" "$ROOT/config/schema.json"; do
    [ -e "$p" ] || { echo "missing install source: $p" >&2; return 1; }
  done
  if [ -f "$ROOT/SHA256SUMS" ]; then
    command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required to verify this install bundle" >&2; return 1; }
    (cd "$ROOT" && sha256sum -c SHA256SUMS >/dev/null) || { echo "install bundle checksum verification failed" >&2; return 1; }
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

snapshot_installation() {
  snapshot="$BACKUP_DIR/install-rollback"
  staging="$snapshot/staging"
  archive="$snapshot/files.tar"
  manifest="$snapshot/manifest.txt"
  services="$snapshot/services.txt"
  rm -rf "$snapshot"
  mkdir -p "$staging"
  : > "$manifest"
  : > "$services"
  for p in $INSTALL_TARGETS; do
    case "$p" in
      /) echo "unsafe install target: /" >&2; return 1 ;;
      /*) ;;
      *) echo "unsafe non-absolute install target: $p" >&2; return 1 ;;
    esac
    if [ -e "$p" ]; then
      relative="${p#/}"
      mkdir -p "$staging/$(dirname "$relative")"
      cp -R "$p" "$staging/$relative"
      echo "present|$p" >> "$manifest"
    else
      echo "absent|$p" >> "$manifest"
    fi
  done
  for service in $SERVICES; do
    init="$INIT_DIR/$service"
    enabled=0
    running=0
    [ -x "$init" ] && "$init" enabled >/dev/null 2>&1 && enabled=1
    [ -x "$init" ] && "$init" running >/dev/null 2>&1 && running=1
    echo "$service|$enabled|$running" >> "$services"
  done
  "$TAR_BIN" -C "$staging" -cf "$archive.tmp" .
  mv "$archive.tmp" "$archive"
  "$TAR_BIN" -tf "$archive" >/dev/null
  rm -rf "$staging"
}

restore_installation() {
  snapshot="$BACKUP_DIR/install-rollback"
  archive="$snapshot/files.tar"
  manifest="$snapshot/manifest.txt"
  services="$snapshot/services.txt"
  [ -s "$manifest" ] && [ -s "$archive" ] || {
    echo "automatic install rollback unavailable: invalid snapshot" >&2
    return 1
  }
  for service in $SERVICES; do
    init="$INIT_DIR/$service"
    [ -x "$init" ] && "$init" stop >/dev/null 2>&1 || true
    [ -x "$init" ] && "$init" disable >/dev/null 2>&1 || true
  done
  while IFS='|' read -r presence p; do
    [ "$presence" = "present" ] || [ "$presence" = "absent" ] || continue
    rm -rf "$p"
  done < "$manifest"
  "$TAR_BIN" -C / -xf "$archive"
  if [ -s "$services" ]; then
    while IFS='|' read -r service enabled running; do
      init="$INIT_DIR/$service"
      [ -x "$init" ] || continue
      if [ "$enabled" = "1" ]; then "$init" enable >/dev/null 2>&1 || true; else "$init" disable >/dev/null 2>&1 || true; fi
      [ "$running" = "1" ] && "$init" start >/dev/null 2>&1 || true
    done < "$services"
  fi
  echo "install_rollback=restored" >&2
}

service_was_running() {
  service="$1"
  grep -F "$service|" "$BACKUP_DIR/install-rollback/services.txt" 2>/dev/null | grep -F '|1' >/dev/null 2>&1
}

wait_control_health() {
  command -v wget >/dev/null 2>&1 || { echo "wget is required to verify the control plane" >&2; return 1; }
  attempt=0
  while [ "$attempt" -lt 20 ]; do
    if wget -q -O "$RUNTIME_DIR/install-health.json" http://127.0.0.1:8787/api/v1/health; then
      echo "control_plane_health=ok"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "control plane did not become healthy after ${attempt}s" >&2
  return 1
}

restart_running_services() {
  for service in router-policy-xray router-policy-zapret router-policy router-policy-watchdog; do
    service_was_running "$service" || continue
    "$INIT_DIR/$service" restart
    "$INIT_DIR/$service" running
  done
  if service_was_running router-policy; then
    wait_control_health
  fi
}

start_control_services() {
  for service in router-policy router-policy-watchdog; do
    if ! "$INIT_DIR/$service" running >/dev/null 2>&1; then
      "$INIT_DIR/$service" start
    fi
    "$INIT_DIR/$service" running
  done
  wait_control_health
}

install_exit() {
  status="$1"
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "${INSTALL_ROLLBACK_ARMED:-0}" = "1" ]; then
    restore_installation || echo "automatic install rollback failed; backup=$BACKUP_DIR" >&2
  fi
  exit "$status"
}

atomic_copy() {
  source="$1"
  target="$2"
  mode_bits="$3"
  mkdir -p "$(dirname "$target")"
  tmp="$target.install.$$"
  rm -rf "$tmp"
  cp "$source" "$tmp"
  chmod "$mode_bits" "$tmp"
  mv "$tmp" "$target"
}

install_files() {
  mkdir -p "$(dirname "$PREFIX")" "$ETC_DIR/config" "$ETC_DIR/secrets" "$ETC_DIR/xray" "$ETC_DIR/zapret" "$ETC_DIR/firewall" "$STATE_DIR/last-good" "$RUNTIME_DIR" "$BIN_DIR" "$INIT_DIR" "$RC_DIR" "$HOTPLUG_IFACE_DIR" "$HOTPLUG_FIREWALL_DIR" "$DNSMASQ_DIR"
  staged_prefix="$PREFIX.install.$$"
  old_prefix="$PREFIX.old.$$"
  rm -rf "$staged_prefix" "$old_prefix"
  mkdir -p "$staged_prefix"
  cp -R "$ROOT/scripts" "$staged_prefix/"
  cp -R "$ROOT/openwrt" "$staged_prefix/"
  chmod +x "$staged_prefix/openwrt/adapter.sh"
  [ ! -e "$PREFIX" ] || mv "$PREFIX" "$old_prefix"
  mv "$staged_prefix" "$PREFIX"
  rm -rf "$old_prefix"
  atomic_copy "$SOURCE_BINARY" "$ROUTER_POLICY_BIN" 755
  if [ ! -f "$ETC_DIR/config/default.json" ]; then
    atomic_copy "$ROOT/config/default.json" "$ETC_DIR/config/default.json" 600
  else
    atomic_copy "$ROOT/config/default.json" "$ETC_DIR/config/factory-default.json" 600
  fi
  atomic_copy "$ROOT/config/schema.json" "$ETC_DIR/config/schema.json" 600
  if [ ! -f "$ETC_DIR/secrets/vpn-subscription-url" ]; then
    : > "$ETC_DIR/secrets/vpn-subscription-url"
  fi
  chmod 700 "$ETC_DIR/secrets"
  for secret in "$ETC_DIR/secrets/"*; do
    [ -e "$secret" ] && chmod 600 "$secret"
  done
  atomic_copy "$ROOT/openwrt/init.d/router-policy" "$INIT_DIR/router-policy" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-boot-guard" "$INIT_DIR/router-policy-boot-guard" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-watchdog" "$INIT_DIR/router-policy-watchdog" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-xray" "$INIT_DIR/router-policy-xray" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-zapret" "$INIT_DIR/router-policy-zapret" 755
  atomic_copy "$ROOT/openwrt/hotplug/iface/95-router-policy" "$HOTPLUG_IFACE_DIR/95-router-policy" 755
  atomic_copy "$ROOT/openwrt/hotplug/firewall/95-router-policy" "$HOTPLUG_FIREWALL_DIR/95-router-policy" 755
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
    preflight_install
    mkdir -p "$STATE_DIR"
    snapshot_installation
    INSTALL_ROLLBACK_ARMED=1
    trap 'install_exit $?' EXIT
    trap 'exit 130' INT HUP
    trap 'exit 143' TERM
    detect
    backup
    install_files
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" validate-config
    echo "== setup token =="
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" auth setup-token --if-needed
    restart_running_services
    if [ "$enable_services" = "1" ]; then
      "$INIT_DIR/router-policy-boot-guard" enable
      "$INIT_DIR/router-policy" enable
      "$INIT_DIR/router-policy-watchdog" enable
      start_control_services
      echo "services_enabled=router-policy-boot-guard router-policy router-policy-watchdog"
      echo "control_services_running=router-policy router-policy-watchdog"
      echo "dataplane_services_boot_enabled=false"
    else
      echo "services_enabled=false"
      echo "enable_services_with=install.sh --install --enable-services"
    fi
    INSTALL_ROLLBACK_ARMED=0
    trap - EXIT INT HUP TERM
    echo "installed=true"
    echo "backup=$BACKUP_DIR"
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
