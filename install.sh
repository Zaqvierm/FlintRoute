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
DNSMASQ_DIR="${DNSMASQ_DIR:-$SYSTEM_ROOT/tmp/dnsmasq.d}"
ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-$BIN_DIR/router-policy}"
SOURCE_BINARY="${SOURCE_BINARY:-$ROOT/dist/router-policy-linux-arm64}"
BACKUP_ROOT="${BACKUP_ROOT:-$SYSTEM_ROOT/root/router-policy-backups}"
BACKUP_DIR="${BACKUP_DIR:-$BACKUP_ROOT/install-$(date -u +%Y%m%dT%H%M%SZ)}"
ROUTER_POLICY_VERSION="${ROUTER_POLICY_VERSION:-unknown}"
BACKUP_SOURCES="${BACKUP_SOURCES:-$SYSTEM_ROOT/etc/config/network $SYSTEM_ROOT/etc/config/firewall $SYSTEM_ROOT/etc/config/dhcp $SYSTEM_ROOT/etc/dnsmasq.d $SYSTEM_ROOT/etc/nftables.d $ETC_DIR}"
TAR_BIN="${TAR_BIN:-tar}"
UBUS_BIN="${UBUS_BIN:-ubus}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
SERVICES="router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
ENABLE_SERVICES="router-policy-boot-guard $SERVICES"
INSTALL_TARGETS="$PREFIX $ROUTER_POLICY_BIN $INIT_DIR/router-policy $INIT_DIR/router-policy-boot-guard $INIT_DIR/router-policy-watchdog $INIT_DIR/router-policy-xray $INIT_DIR/router-policy-zapret $HOTPLUG_IFACE_DIR/95-router-policy $HOTPLUG_FIREWALL_DIR/95-router-policy $ETC_DIR/config/default.json $ETC_DIR/config/factory-default.json $ETC_DIR/config/schema.json $ETC_DIR/config/listener.conf $ETC_DIR/secrets/vpn-subscription-url $STATE_DIR/last-backup-path $STATE_DIR/auth/setup-token.json"

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

regular_file_mode_matches() {
  target="$1"
  mode_bits="$2"
  # Targets are fixed allowlisted paths; only the leading permission field is read.
  # shellcheck disable=SC2012
  permissions="$(LC_ALL=C ls -ld "$target" 2>/dev/null | awk '{print substr($1, 1, 10)}')"
  case "$mode_bits:$permissions" in
    600:-rw-------|644:-rw-r--r--|700:-rwx------|755:-rwxr-xr-x) return 0 ;;
    *) return 1 ;;
  esac
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    echo "neither sha256sum nor openssl is available" >&2
    return 1
  fi
}

is_install_target() {
  candidate_path="$1"
  for allowed_path in $INSTALL_TARGETS; do
    [ "$candidate_path" != "$allowed_path" ] || return 0
  done
  return 1
}

is_managed_service() {
  candidate_service="$1"
  for allowed_service in $ENABLE_SERVICES; do
    [ "$candidate_service" != "$allowed_service" ] || return 0
  done
  return 1
}

validate_install_snapshot_metadata() {
  snapshot_manifest="$1"
  snapshot_services="$2"
  while IFS='|' read -r presence target extra; do
    [ -z "$extra" ] || {
      echo "automatic install rollback unavailable: malformed snapshot manifest" >&2
      return 1
    }
    [ "$presence" = "present" ] || [ "$presence" = "absent" ] || {
      echo "automatic install rollback unavailable: malformed snapshot manifest" >&2
      return 1
    }
    is_install_target "$target" || {
      echo "automatic install rollback unavailable: unowned snapshot target" >&2
      return 1
    }
  done < "$snapshot_manifest"
  for allowed_path in $INSTALL_TARGETS; do
    target_count=0
    while IFS='|' read -r _ target _; do
      [ "$target" != "$allowed_path" ] || target_count=$((target_count + 1))
    done < "$snapshot_manifest"
    [ "$target_count" -eq 1 ] || {
      echo "automatic install rollback unavailable: incomplete snapshot manifest" >&2
      return 1
    }
  done
  while IFS='|' read -r service enabled running extra; do
    case "$extra|$enabled|$running" in
      "|0|0"|"|0|1"|"|1|0"|"|1|1") ;;
      *)
        echo "automatic install rollback unavailable: malformed service manifest" >&2
        return 1
        ;;
    esac
    is_managed_service "$service" || {
      echo "automatic install rollback unavailable: unowned service manifest entry" >&2
      return 1
    }
  done < "$snapshot_services"
  for allowed_service in $ENABLE_SERVICES; do
    service_count=0
    while IFS='|' read -r service _ _; do
      [ "$service" != "$allowed_service" ] || service_count=$((service_count + 1))
    done < "$snapshot_services"
    [ "$service_count" -eq 1 ] || {
      echo "automatic install rollback unavailable: incomplete service manifest" >&2
      return 1
    }
  done
}

run_bounded() {
  "$TIMEOUT_BIN" 15 "$@"
}

preflight_runtime() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  command -v "$TIMEOUT_BIN" >/dev/null 2>&1 || {
    echo "timeout is required for bounded OpenWrt service operations" >&2
    return 1
  }
  command -v "$UBUS_BIN" >/dev/null 2>&1 || {
    echo "ubus is required for OpenWrt install safety checks" >&2
    return 1
  }
  if ! "$TIMEOUT_BIN" 8 "$UBUS_BIN" -t 5 call system board >/dev/null 2>&1; then
    echo "install blocked: ubus system state is unavailable" >&2
    return 1
  fi
  if ! "$TIMEOUT_BIN" 8 "$UBUS_BIN" -t 5 call service list '{}' >/dev/null 2>&1; then
    echo "install blocked: procd service state is unavailable" >&2
    return 1
  fi
  if command -v nft >/dev/null 2>&1 && nft list table inet router_policy_boot_guard >/dev/null 2>&1; then
    echo "install blocked: forwarding boot guard is still active" >&2
    return 1
  fi
  if [ -x "$INIT_DIR/router-policy" ] && run_bounded "$INIT_DIR/router-policy" running >/dev/null 2>&1; then
    wait_control_health
    if [ ! -x "$ROUTER_POLICY_BIN" ] || ! run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" maintenance status >/dev/null 2>&1; then
      echo "install blocked: running controller does not support safe maintenance; stop router-policy and its watchdog before retrying" >&2
      return 1
    fi
  fi
}

detect() {
  echo "== detect =="
  uname -a || true
  [ -f /etc/openwrt_release ] && cat /etc/openwrt_release || true
  command -v "$UBUS_BIN" >/dev/null 2>&1 && command -v "$TIMEOUT_BIN" >/dev/null 2>&1 && "$TIMEOUT_BIN" 8 "$UBUS_BIN" -t 5 call system board || true
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
  archive_hash="$(hash_file "$archive")" || return 1
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
  archive_hash_file="$snapshot/files.sha256"
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
  for service in $ENABLE_SERVICES; do
    init="$INIT_DIR/$service"
    enabled=0
    running=0
    if [ -z "$SYSTEM_ROOT" ]; then
      [ -x "$init" ] && run_bounded "$init" enabled >/dev/null 2>&1 && enabled=1
      if [ "$service" != "router-policy-boot-guard" ]; then
        [ -x "$init" ] && run_bounded "$init" running >/dev/null 2>&1 && running=1
      fi
    fi
    echo "$service|$enabled|$running" >> "$services"
  done
  "$TAR_BIN" -C "$staging" -cf "$archive.tmp" .
  mv "$archive.tmp" "$archive"
  "$TAR_BIN" -tf "$archive" >/dev/null
  hash_file "$archive" > "$archive_hash_file.tmp"
  mv "$archive_hash_file.tmp" "$archive_hash_file"
  rm -rf "$staging"
}

restore_installation() {
  snapshot="$BACKUP_DIR/install-rollback"
  archive="$snapshot/files.tar"
  archive_hash_file="$snapshot/files.sha256"
  manifest="$snapshot/manifest.txt"
  services="$snapshot/services.txt"
  [ -s "$manifest" ] && [ -s "$archive" ] && [ -s "$archive_hash_file" ] && [ -s "$services" ] || {
    echo "automatic install rollback unavailable: invalid snapshot" >&2
    return 1
  }
  [ ! -L "$manifest" ] && [ ! -L "$archive" ] && [ ! -L "$archive_hash_file" ] && [ ! -L "$services" ] || {
    echo "automatic install rollback unavailable: symlinked snapshot metadata" >&2
    return 1
  }
  expected_archive_hash="$(cat "$archive_hash_file")"
  actual_archive_hash="$(hash_file "$archive")" || return 1
  [ "$expected_archive_hash" = "$actual_archive_hash" ] || {
    echo "automatic install rollback unavailable: snapshot hash mismatch" >&2
    return 1
  }
  "$TAR_BIN" -tf "$archive" >/dev/null || {
    echo "automatic install rollback unavailable: unreadable snapshot archive" >&2
    return 1
  }
  validate_install_snapshot_metadata "$manifest" "$services" || return 1
  service_restore_ok=1
  if [ -z "$SYSTEM_ROOT" ]; then
    for service in router-policy-watchdog router-policy; do
      init="$INIT_DIR/$service"
      [ ! -x "$init" ] || run_bounded "$init" stop >/dev/null 2>&1 || service_restore_ok=0
    done
    if [ -x "$INIT_DIR/router-policy-boot-guard" ]; then
      run_bounded "$INIT_DIR/router-policy-boot-guard" stop >/dev/null 2>&1 || service_restore_ok=0
    fi
  fi
  while IFS='|' read -r presence p; do
    [ "$presence" = "present" ] || [ "$presence" = "absent" ] || continue
    rm -rf "$p"
  done < "$manifest"
  "$TAR_BIN" -C / -xf "$archive"
  if [ -z "$SYSTEM_ROOT" ] && [ -s "$services" ]; then
    while IFS='|' read -r service enabled running; do
      init="$INIT_DIR/$service"
      [ -x "$init" ] || continue
      if [ "$enabled" = "1" ]; then
        run_bounded "$init" enable >/dev/null 2>&1 || service_restore_ok=0
      else
        run_bounded "$init" disable >/dev/null 2>&1 || service_restore_ok=0
      fi
    done < "$services"
    if [ "$service_restore_ok" = "1" ] && service_was_running router-policy; then
      run_bounded "$INIT_DIR/router-policy" start >/dev/null 2>&1 || service_restore_ok=0
      [ "$service_restore_ok" != "1" ] || wait_control_health || service_restore_ok=0
    fi
    for service in router-policy-xray router-policy-zapret; do
      init="$INIT_DIR/$service"
      [ -x "$init" ] || continue
      if service_was_running "$service"; then
        run_bounded "$init" running >/dev/null 2>&1 || service_restore_ok=0
      else
        if run_bounded "$init" running >/dev/null 2>&1; then service_restore_ok=0; fi
      fi
    done
    if [ "$service_restore_ok" = "1" ] && service_was_running router-policy-watchdog; then
      run_bounded "$INIT_DIR/router-policy-watchdog" start >/dev/null 2>&1 || service_restore_ok=0
      [ "$service_restore_ok" != "1" ] || run_bounded "$INIT_DIR/router-policy-watchdog" running >/dev/null 2>&1 || service_restore_ok=0
    fi
  fi
  if [ "$service_restore_ok" != "1" ]; then
    echo "install_rollback=files-restored-services-unverified" >&2
    return 1
  fi
  echo "install_rollback=restored" >&2
}

service_was_running() {
  service="$1"
  awk -F '|' -v service="$service" '$1 == service && $3 == "1" { found=1 } END { exit(found ? 0 : 1) }' "$BACKUP_DIR/install-rollback/services.txt" 2>/dev/null
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
  [ -z "$SYSTEM_ROOT" ] || return 0
  if service_was_running router-policy; then
    run_bounded "$INIT_DIR/router-policy" restart
    run_bounded "$INIT_DIR/router-policy" running
    wait_control_health
  fi
  for service in router-policy-xray router-policy-zapret; do
    init="$INIT_DIR/$service"
    [ -x "$init" ] || continue
    if service_was_running "$service"; then
      run_bounded "$init" running >/dev/null 2>&1 || {
        echo "install blocked: production $service changed state during upgrade" >&2
        return 1
      }
    else
      if run_bounded "$init" running >/dev/null 2>&1; then
        echo "install blocked: production $service started unexpectedly during upgrade" >&2
        return 1
      fi
    fi
  done
  if service_was_running router-policy-watchdog; then
    run_bounded "$INIT_DIR/router-policy-watchdog" restart
    run_bounded "$INIT_DIR/router-policy-watchdog" running
  fi
}

start_control_services() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  for service in router-policy router-policy-watchdog; do
    if ! "$INIT_DIR/$service" running >/dev/null 2>&1; then
      run_bounded "$INIT_DIR/$service" start
    fi
    run_bounded "$INIT_DIR/$service" running
  done
  wait_control_health
}

begin_maintenance() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  [ -x "$ROUTER_POLICY_BIN" ] || return 0
  if run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" maintenance status >/dev/null 2>&1; then
    run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" maintenance begin --owner "installer:install-$$" --reason upgrade --lease 30m >/dev/null
    return 0
  fi
  if [ -x "$INIT_DIR/router-policy" ] && run_bounded "$INIT_DIR/router-policy" running >/dev/null 2>&1; then
    echo "install blocked: running controller cannot enter maintenance" >&2
    return 1
  fi
  legacy_watchdog="$INIT_DIR/router-policy-watchdog"
  if [ -x "$legacy_watchdog" ] && run_bounded "$legacy_watchdog" running >/dev/null 2>&1; then
    run_bounded "$legacy_watchdog" stop >/dev/null 2>&1
    echo "maintenance=legacy-watchdog-stopped"
  fi
}

end_maintenance() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  [ -x "$ROUTER_POLICY_BIN" ] || return 0
  run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" maintenance end >/dev/null 2>&1 || true
}

install_exit() {
  status="$1"
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "${INSTALL_ROLLBACK_ARMED:-0}" = "1" ]; then
    restore_installation || echo "automatic install rollback failed; backup=$BACKUP_DIR" >&2
  fi
  end_maintenance
  exit "$status"
}

atomic_copy() {
  source="$1"
  target="$2"
  mode_bits="$3"
  mkdir -p "$(dirname "$target")"
  [ ! -L "$target" ] || { echo "refusing symlink install target: $target" >&2; return 1; }
  if [ -f "$target" ] && cmp -s "$source" "$target" && regular_file_mode_matches "$target" "$mode_bits"; then
    return 0
  fi
  tmp="$(mktemp "$target.install.XXXXXX")"
  if ! cp "$source" "$tmp" || ! chmod "$mode_bits" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if [ -z "$SYSTEM_ROOT" ]; then
    if ! chown 0:0 "$tmp"; then
      rm -f "$tmp"
      return 1
    fi
  fi
  if ! { sync -f "$tmp" 2>/dev/null || sync "$tmp" 2>/dev/null || sync; } || ! mv "$tmp" "$target"; then
    rm -f "$tmp"
    return 1
  fi
  sync -f "$(dirname "$target")" 2>/dev/null || true
}

install_files() {
  mkdir -p "$(dirname "$PREFIX")" "$ETC_DIR/config" "$ETC_DIR/secrets" "$ETC_DIR/xray" "$ETC_DIR/zapret" "$ETC_DIR/firewall" "$STATE_DIR/last-good" "$RUNTIME_DIR" "$BIN_DIR" "$INIT_DIR" "$RC_DIR" "$HOTPLUG_IFACE_DIR" "$HOTPLUG_FIREWALL_DIR" "$DNSMASQ_DIR"
  staged_prefix="$PREFIX.install.$$"
  old_prefix="$PREFIX.old.$$"
  rm -rf "$staged_prefix" "$old_prefix"
  mkdir -p "$staged_prefix"
  cp -R "$ROOT/scripts" "$staged_prefix/"
  cp -R "$ROOT/openwrt" "$staged_prefix/"
  chmod +x "$staged_prefix/scripts/"*.sh
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
  if [ -L "$ETC_DIR/config/listener.conf" ]; then
    echo "refusing symlink listener config: $ETC_DIR/config/listener.conf" >&2
    return 1
  fi
  if [ ! -f "$ETC_DIR/config/listener.conf" ]; then
    atomic_copy "$ROOT/config/listener.conf" "$ETC_DIR/config/listener.conf" 600
  fi
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
  echo "would_install_zapret_calibration_runner=$PREFIX/scripts/calibrate-zapret.sh"
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
    preflight_runtime
    mkdir -p "$STATE_DIR"
    snapshot_installation
    INSTALL_ROLLBACK_ARMED=1
    trap 'install_exit $?' EXIT
    trap 'exit 130' INT HUP
    trap 'exit 143' TERM
    detect
    backup
    begin_maintenance
    install_files
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" validate-config
    "$ROUTER_POLICY_BIN" backup register --root "$BACKUP_DIR" --operation "$(basename "$BACKUP_DIR")" --version "$ROUTER_POLICY_VERSION" --reason install --retention-class installer-fallback >/dev/null
    "$ROUTER_POLICY_BIN" backup prune --root "$BACKUP_ROOT" --max 2 --max-bytes 134217728 --apply >/dev/null
    echo "== setup token =="
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" auth setup-token --if-needed
    restart_running_services
    if [ "$enable_services" = "1" ]; then
      run_bounded "$INIT_DIR/router-policy-boot-guard" enable
      run_bounded "$INIT_DIR/router-policy" enable
      run_bounded "$INIT_DIR/router-policy-watchdog" enable
      start_control_services
      echo "services_enabled=router-policy-boot-guard router-policy router-policy-watchdog"
      echo "control_services_running=router-policy router-policy-watchdog"
      echo "dataplane_services_boot_enabled=false"
    else
      echo "services_enabled=false"
      echo "enable_services_with=install.sh --install --enable-services"
    fi
    INSTALL_ROLLBACK_ARMED=0
    end_maintenance
    trap - EXIT INT HUP TERM
    echo "installed=true"
    echo "backup=$BACKUP_DIR"
    echo "zapret_calibration=pending-observed-domain"
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
