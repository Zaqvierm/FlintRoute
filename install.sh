#!/bin/sh
set -eu
umask 077

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
SYSTEM_ROOT="${ROUTER_POLICY_SYSTEM_ROOT:-}"
PREFIX="${PREFIX:-$SYSTEM_ROOT/usr/lib/router-policy}"
ETC_DIR="${ETC_DIR:-$SYSTEM_ROOT/etc/router-policy}"
STATE_DIR="${STATE_DIR:-$ETC_DIR/state}"
STATE_DATABASE="${STATE_DATABASE:-$STATE_DIR/router-policy.bbolt}"
RUNTIME_DIR="${RUNTIME_DIR:-$SYSTEM_ROOT/tmp/router-policy}"
BIN_DIR="${BIN_DIR:-$SYSTEM_ROOT/usr/bin}"
INIT_DIR="${INIT_DIR:-$SYSTEM_ROOT/etc/init.d}"
RC_DIR="${RC_DIR:-$SYSTEM_ROOT/etc/rc.d}"
HOTPLUG_IFACE_DIR="${HOTPLUG_IFACE_DIR:-$SYSTEM_ROOT/etc/hotplug.d/iface}"
HOTPLUG_FIREWALL_DIR="${HOTPLUG_FIREWALL_DIR:-$SYSTEM_ROOT/etc/hotplug.d/firewall}"
DNSMASQ_DIR="${DNSMASQ_DIR:-$SYSTEM_ROOT/tmp/dnsmasq.d}"
ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-$BIN_DIR/router-policy}"
ROUTER_POLICY_HELPER_BIN="${ROUTER_POLICY_HELPER_BIN:-$BIN_DIR/router-policy-helper}"
SOURCE_BINARY="${SOURCE_BINARY:-$ROOT/dist/router-policy-linux-arm64}"
SOURCE_HELPER_BINARY="${SOURCE_HELPER_BINARY:-$ROOT/dist/router-policy-helper-linux-arm64}"
BACKUP_ROOT="${BACKUP_ROOT:-$SYSTEM_ROOT/root/router-policy-backups}"
BACKUP_DIR="${BACKUP_DIR:-$BACKUP_ROOT/install-$(date -u +%Y%m%dT%H%M%SZ)}"
ROUTER_POLICY_VERSION="${ROUTER_POLICY_VERSION:-unknown}"
BACKUP_SOURCES="${BACKUP_SOURCES:-$SYSTEM_ROOT/etc/config/network $SYSTEM_ROOT/etc/config/firewall $SYSTEM_ROOT/etc/config/dhcp $SYSTEM_ROOT/etc/dnsmasq.d $SYSTEM_ROOT/etc/nftables.d $ETC_DIR}"
TAR_BIN="${TAR_BIN:-tar}"
UBUS_BIN="${UBUS_BIN:-ubus}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
SERVICES="router-policy-helper router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
ENABLE_SERVICES="router-policy-dns-observer router-policy-boot-guard $SERVICES"
INSTALL_TARGETS="$PREFIX $ROUTER_POLICY_BIN $ROUTER_POLICY_HELPER_BIN $INIT_DIR/router-policy-helper $INIT_DIR/router-policy $INIT_DIR/router-policy-dns-observer $INIT_DIR/router-policy-boot-guard $INIT_DIR/router-policy-watchdog $INIT_DIR/router-policy-xray $INIT_DIR/router-policy-zapret $HOTPLUG_IFACE_DIR/95-router-policy $HOTPLUG_FIREWALL_DIR/95-router-policy $ETC_DIR/config/default.json $ETC_DIR/config/factory-default.json $ETC_DIR/config/schema.json $ETC_DIR/config/listener.conf $ETC_DIR/secrets/vpn-subscription-url $STATE_DIR/last-backup-path $STATE_DIR/auth/setup-token.json"

# These directories belong to OpenWrt, not to FlintRoute.  They must never be
# represented by a rollback archive entry: restoring synthetic staging
# metadata can make a healthy system unreadable after a failed install.
CRITICAL_SYSTEM_DIRS="$SYSTEM_ROOT $SYSTEM_ROOT/etc $SYSTEM_ROOT/usr $SYSTEM_ROOT/usr/bin $SYSTEM_ROOT/usr/lib $SYSTEM_ROOT/etc/init.d $SYSTEM_ROOT/etc/hotplug.d"

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
  [ -f "$SOURCE_HELPER_BINARY" ] || { echo "missing $SOURCE_HELPER_BINARY; run scripts/build-go.sh before install" >&2; return 1; }
  for p in "$ROOT/scripts" "$ROOT/openwrt" "$ROOT/config/default.json" "$ROOT/config/schema.json"; do
    [ -e "$p" ] || { echo "missing install source: $p" >&2; return 1; }
  done
  if [ -f "$ROOT/SHA256SUMS" ]; then
    command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required to verify this install bundle" >&2; return 1; }
    (cd "$ROOT" && sha256sum -c SHA256SUMS >/dev/null) || { echo "install bundle checksum verification failed" >&2; return 1; }
  fi
  validate_critical_system_dirs && validate_backup_paths
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

is_critical_system_dir() {
  candidate_path="$1"
  for critical_path in $CRITICAL_SYSTEM_DIRS; do
    [ -n "$critical_path" ] && [ "$candidate_path" = "$critical_path" ] && return 0
  done
  return 1
}

validate_no_symlink_path() {
  candidate="$1"
  case "$candidate" in
    /*) ;;
    *) return 1 ;;
  esac
  # The installer accepts paths from environment overrides (and reuses this
  # validator for snapshot manifests).  Lexical paths containing dot
  # components are not safe ownership identifiers: /usr/lib/../bin and
  # /etc/./init.d can evade exact allowlist comparisons while targeting a
  # different object after the kernel resolves them.  Empty components also
  # make canonical identity ambiguous (//etc, /etc//router-policy).
  [ "$candidate" != "/" ] || return 1
  case "$candidate" in
    */) return 1 ;;
  esac
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

validate_backup_paths() {
  case "$BACKUP_ROOT:$BACKUP_DIR" in
    "":*|*:|/:*|*:/) echo "install blocked: invalid backup root" >&2; return 1 ;;
  esac
  case "$BACKUP_DIR" in
    "$BACKUP_ROOT"/*) ;;
    *) echo "install blocked: backup directory is outside backup root" >&2; return 1 ;;
  esac
  validate_no_symlink_path "$BACKUP_ROOT" || {
    echo "install blocked: symlink in backup root path" >&2
    return 1
  }
  for critical_path in $CRITICAL_SYSTEM_DIRS; do
    [ -n "$critical_path" ] || continue
    case "$BACKUP_ROOT/" in
      "$critical_path"/*) echo "install blocked: backup root is inside a system directory: $BACKUP_ROOT" >&2; return 1 ;;
    esac
  done
}

is_managed_service() {
  candidate_service="$1"
  for allowed_service in $ENABLE_SERVICES; do
    [ "$candidate_service" != "$allowed_service" ] || return 0
  done
  return 1
}

path_metadata() {
  target="$1"
  # OpenWrt BusyBox and GNU stat both support -c for these fields.
  # Git Bash's stat emulation includes the caller umask in its displayed mode;
  # inspect with a neutral umask so the invariant is about the object itself.
  (umask 022; stat -c '%a|%u|%g' "$target" 2>/dev/null)
}

copy_preserving_metadata() {
  source_path="$1"
  target_path="$2"
  # BusyBox and GNU cp both provide -a.  Unlike cp -R this retains nested
  # modes, uid/gid and symlink identity inside a FlintRoute-owned tree.
  cp -a "$source_path" "$target_path"
}

validate_critical_system_dirs() {
  # Library/tests may source this script on a developer host where /etc is
  # not an OpenWrt tree. Real root installs are gated by openwrt_release;
  # synthetic trees use SYSTEM_ROOT explicitly.
  if [ -z "$SYSTEM_ROOT" ] && [ ! -f /etc/openwrt_release ]; then
    return 0
  fi
  for target in $CRITICAL_SYSTEM_DIRS; do
    [ -n "$target" ] || continue
    [ -d "$target" ] || {
      echo "install blocked: critical system directory is missing: $target" >&2
      return 1
    }
    [ ! -L "$target" ] || {
      echo "install blocked: critical system directory is a symlink: $target" >&2
      return 1
    }
    metadata=$(path_metadata "$target") || {
      echo "install blocked: cannot inspect critical system directory: $target" >&2
      return 1
    }
    directory_mode=${metadata%%|*}
    reference="${SYSTEM_ROOT:-}/rom${target#"${SYSTEM_ROOT:-}"}"
    if [ -e "$reference" ] && [ ! -L "$reference" ]; then
      reference_metadata=$(path_metadata "$reference") || {
        echo "install blocked: cannot inspect ROM directory: $reference" >&2
        return 1
      }
      reference_mode=${reference_metadata%%|*}
      [ "$directory_mode" = "$reference_mode" ] || {
        echo "install blocked: critical directory mode differs from ROM: $target mode=$directory_mode rom=$reference_mode" >&2
        return 1
      }
    else
      case "$target:$directory_mode" in
        "$SYSTEM_ROOT:755"|"$SYSTEM_ROOT/etc:755"|"$SYSTEM_ROOT/usr:755"|"$SYSTEM_ROOT/usr/bin:755"|"$SYSTEM_ROOT/usr/lib:755"|"$SYSTEM_ROOT/etc/init.d:755"|"$SYSTEM_ROOT/etc/hotplug.d:755") ;;
        *)
          echo "install blocked: suspicious critical directory mode: $target mode=$directory_mode" >&2
          return 1
          ;;
      esac
    fi
  done
}

validate_install_snapshot_metadata() {
  snapshot_manifest="$1"
  snapshot_services="$2"
  while IFS='|' read -r presence target target_mode uid gid extra; do
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
    validate_no_symlink_path "$target" || {
      echo "automatic install rollback unavailable: symlink in target path" >&2
      return 1
    }
    is_critical_system_dir "$target" && {
      echo "automatic install rollback unavailable: critical system directory in snapshot" >&2
      return 1
    }
    case "$presence" in
      present)
        if [ -n "$target_mode$uid$gid" ]; then
          case "$target_mode" in ''|*[!0-7]*) echo "automatic install rollback unavailable: malformed target mode" >&2; return 1 ;; esac
          case "$uid:$gid" in *[!0-9:]*|*:|:*) echo "automatic install rollback unavailable: malformed target ownership" >&2; return 1 ;; esac
        fi
        ;;
      absent)
        [ -z "$target_mode" ] && [ -z "$uid" ] && [ -z "$gid" ] || {
          echo "automatic install rollback unavailable: absent target has metadata" >&2
          return 1
        }
        ;;
    esac
  done < "$snapshot_manifest"
  for allowed_path in $INSTALL_TARGETS; do
    target_count=0
    while IFS='|' read -r _ target _ _ _ _; do
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

wait_service_stopped() {
  init="$1"
  attempt=0
  while [ "$attempt" -lt 15 ]; do
    if ! run_bounded "$init" running >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  return 1
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
    PREINSTALL_ACTIVE_REVISION="$(health_json_field active_revision "$RUNTIME_DIR/install-health.json")"
    export PREINSTALL_ACTIVE_REVISION
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
  validate_backup_paths || return 1
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
      copy_preserving_metadata "$p" "$staging/$relative"
      echo "$p" >> "$manifest"
      backup_items=$((backup_items + 1))
    fi
  done
  [ "$backup_items" -gt 0 ] || { echo "backup has no source files" >&2; return 1; }
  # Do not store the synthetic staging root or its umask-derived parents.
  # This archive is an export backup, but keeping only allowlisted descendants
  # makes accidental future restore code unable to replay /etc or /usr modes.
  file_list="$BACKUP_DIR/files.list"
  (cd "$staging" && find . -mindepth 1 -print | sed 's#^\./##' > "$file_list") || {
    rm -f "$file_list"
    return 1
  }
  (cd "$staging" && "$TAR_BIN" -cf "$archive.tmp" -T "$file_list") || {
    rm -f "$file_list" "$archive.tmp"
    return 1
  }
  rm -f "$file_list"
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
  validate_backup_paths || return 1
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
    is_critical_system_dir "$p" && { echo "unsafe critical system install target: $p" >&2; return 1; }
    validate_no_symlink_path "$p" || { echo "unsafe symlink in install target path: $p" >&2; return 1; }
    if [ -e "$p" ]; then
      [ ! -L "$p" ] || { echo "unsafe symlink install target: $p" >&2; return 1; }
      relative="${p#/}"
      mkdir -p "$staging/$(dirname "$relative")"
      copy_preserving_metadata "$p" "$staging/$relative"
      metadata=$(path_metadata "$p") || { echo "unable to snapshot metadata: $p" >&2; return 1; }
      target_mode=${metadata%%|*}; ownership=${metadata#*|}; uid=${ownership%%|*}; gid=${ownership#*|}
      echo "present|$p|$target_mode|$uid|$gid" >> "$manifest"
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
  # Archive only the exact allowlisted targets recorded in the manifest.  Do
  # not feed find(1) the staging tree: synthetic parents such as usr/ and
  # usr/lib/ inherit umask 077 and must never become archive members, even if
  # restore later extracts into a private directory.
  file_list="$snapshot/files.list"
  : > "$file_list"
  while IFS='|' read -r presence p target_mode uid gid; do
    [ "$presence" = "present" ] || continue
    relative="${p#/}"
    [ -n "$relative" ] || { rm -f "$file_list"; return 1; }
    printf '%s\n' "$relative" >> "$file_list"
  done < "$manifest"
  (cd "$staging" && "$TAR_BIN" -cf "$archive.tmp" -T "$file_list") || {
    rm -f "$file_list" "$archive.tmp"
    return 1
  }
  rm -f "$file_list"
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
  validate_critical_system_dirs || {
    echo "automatic install rollback blocked: critical system directory invariant failed" >&2
    return 1
  }
  service_restore_ok=1
  if [ -z "$SYSTEM_ROOT" ]; then
    for service in router-policy-watchdog router-policy; do
      init="$INIT_DIR/$service"
      if [ -x "$init" ] && run_bounded "$init" running >/dev/null 2>&1; then
        run_bounded "$init" stop >/dev/null 2>&1 || service_restore_ok=0
      fi
      if [ -x "$init" ] && ! wait_service_stopped "$init"; then
        service_restore_ok=0
      fi
    done
    if [ -x "$INIT_DIR/router-policy-boot-guard" ]; then
      run_bounded "$INIT_DIR/router-policy-boot-guard" stop >/dev/null 2>&1 || {
        if command -v nft >/dev/null 2>&1 && nft list table inet router_policy_boot_guard >/dev/null 2>&1; then
          service_restore_ok=0
        fi
      }
    fi
  fi
  if [ "$service_restore_ok" != "1" ]; then
    echo "install_rollback=blocked-managed-services-still-running" >&2
    return 1
  fi
  restore_staging="$snapshot/restore.$$"
  rm -rf "$restore_staging"
  mkdir -p "$restore_staging"
  "$TAR_BIN" -C "$restore_staging" -xf "$archive" || {
    rm -rf "$restore_staging"
    echo "automatic install rollback unavailable: snapshot extraction failed" >&2
    return 1
  }
  while IFS='|' read -r presence p target_mode uid gid; do
    [ "$presence" = "present" ] || [ "$presence" = "absent" ] || continue
    rm -rf "$p"
    if [ "$presence" = "present" ]; then
      relative="${p#/}"
      source="$restore_staging/$relative"
      [ -e "$source" ] || {
        rm -rf "$restore_staging"
        echo "automatic install rollback unavailable: missing allowlisted target in snapshot: $p" >&2
        return 1
      }
      parent_dir=$(dirname "$p")
      [ -d "$parent_dir" ] || {
        rm -rf "$restore_staging"
        echo "automatic install rollback blocked: target parent is missing: $parent_dir" >&2
        return 1
      }
      validate_no_symlink_path "$p" || {
        rm -rf "$restore_staging"
        echo "automatic install rollback blocked: symlink in target path: $p" >&2
        return 1
      }
      mkdir -p "$(dirname "$p")"
      copy_preserving_metadata "$source" "$p"
      if [ -z "$target_mode$uid$gid" ]; then
        metadata=$(path_metadata "$source") || { rm -rf "$restore_staging"; return 1; }
        target_mode=${metadata%%|*}; ownership=${metadata#*|}; uid=${ownership%%|*}; gid=${ownership#*|}
      fi
      chmod "$target_mode" "$p" || { rm -rf "$restore_staging"; return 1; }
      if [ "$(id -u)" = "0" ] && command -v chown >/dev/null 2>&1; then
        chown "$uid:$gid" "$p" || { rm -rf "$restore_staging"; return 1; }
      fi
    fi
  done < "$manifest"
  rm -rf "$restore_staging"
  restore_state_database || return 1
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

snapshot_state_database() {
  snapshot="$BACKUP_DIR/install-rollback"
  presence="$snapshot/state-database.presence"
  backup_path="$snapshot/router-policy.bbolt"
  hash_path="$snapshot/router-policy.bbolt.sha256"
  rm -f "$backup_path" "$hash_path"
  if [ ! -e "$STATE_DATABASE" ]; then
    echo "absent" > "$presence"
    return 0
  fi
  [ -f "$STATE_DATABASE" ] && [ ! -L "$STATE_DATABASE" ] || {
    echo "automatic install rollback unavailable: unsafe state database" >&2
    return 1
  }
  cp "$STATE_DATABASE" "$backup_path.tmp"
  mv "$backup_path.tmp" "$backup_path"
  hash_file "$backup_path" > "$hash_path.tmp"
  mv "$hash_path.tmp" "$hash_path"
  if [ -x "$ROUTER_POLICY_BIN" ]; then
    run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" internal-verify-state-backup --path "$backup_path" >/dev/null
  fi
  echo "present" > "$presence"
}

restore_state_database() {
  snapshot="$BACKUP_DIR/install-rollback"
  presence="$snapshot/state-database.presence"
  [ -s "$presence" ] || return 0
  [ ! -L "$presence" ] || {
    echo "automatic install rollback unavailable: symlinked state metadata" >&2
    return 1
  }
  case "$(cat "$presence")" in
    absent)
      rm -f "$STATE_DATABASE"
      ;;
    present)
      backup_path="$snapshot/router-policy.bbolt"
      hash_path="$snapshot/router-policy.bbolt.sha256"
      [ -f "$backup_path" ] && [ ! -L "$backup_path" ] && [ -s "$hash_path" ] && [ ! -L "$hash_path" ] || {
        echo "automatic install rollback unavailable: invalid state backup" >&2
        return 1
      }
      expected_hash="$(cat "$hash_path")"
      actual_hash="$(hash_file "$backup_path")" || return 1
      [ "$expected_hash" = "$actual_hash" ] || {
        echo "automatic install rollback unavailable: state backup hash mismatch" >&2
        return 1
      }
      if [ -x "$ROUTER_POLICY_BIN" ]; then
        run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" internal-verify-state-backup --path "$backup_path" >/dev/null
      fi
      mkdir -p "$(dirname "$STATE_DATABASE")"
      cp "$backup_path" "$STATE_DATABASE.restore.$$"
      chmod 600 "$STATE_DATABASE.restore.$$"
      mv "$STATE_DATABASE.restore.$$" "$STATE_DATABASE"
      ;;
    *)
      echo "automatic install rollback unavailable: invalid state presence marker" >&2
      return 1
      ;;
  esac
}

service_was_running() {
  service="$1"
  awk -F '|' -v service="$service" '$1 == service && $3 == "1" { found=1 } END { exit(found ? 0 : 1) }' "$BACKUP_DIR/install-rollback/services.txt" 2>/dev/null
}

health_json_field() {
  field="$1"
  file="$2"
  tr '{},' '\n' < "$file" | sed -n "s/^[[:space:]]*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*$/\1/p" | head -n 1
}

wait_control_health() {
  expected_revision="${1:-}"
  max_attempts="${ROUTER_POLICY_HEALTH_ATTEMPTS:-120}"
  case "$max_attempts" in *[!0-9]*|'') max_attempts=120 ;; esac
  [ "$max_attempts" -ge 1 ] && [ "$max_attempts" -le 120 ] || max_attempts=120
  command -v wget >/dev/null 2>&1 || { echo "wget is required to verify the control plane" >&2; return 1; }
  attempt=0
  while [ "$attempt" -lt "$max_attempts" ]; do
    if wget -q -O "$RUNTIME_DIR/install-health.json" http://127.0.0.1:8787/api/v1/health; then
      health_status="$(health_json_field status "$RUNTIME_DIR/install-health.json")"
      recovery_status="$(health_json_field recovery_status "$RUNTIME_DIR/install-health.json")"
      active_revision="$(health_json_field active_revision "$RUNTIME_DIR/install-health.json")"
      if [ "$health_status" = "ok" ] && [ "$recovery_status" != "error" ] && [ -n "$active_revision" ] && { [ -z "$expected_revision" ] || [ "$active_revision" = "$expected_revision" ]; }; then
        echo "control_plane_health=ok"
        echo "control_plane_active_revision=$active_revision"
        return 0
      fi
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "control plane did not become healthy after ${attempt}s" >&2
  return 1
}

stop_control_services_for_upgrade() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  for service in router-policy-watchdog router-policy; do
    service_was_running "$service" || continue
    init="$INIT_DIR/$service"
    run_bounded "$init" stop >/dev/null
    if ! wait_service_stopped "$init"; then
      echo "install blocked: $service did not stop cleanly" >&2
      return 1
    fi
  done
}

restart_running_services() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  if service_was_running router-policy; then
    # The controller was intentionally stopped before files were replaced.
    # Calling rc.common restart here issues a second procd delete; some OpenWrt
    # builds return Not found for that already-absent service and abort a healthy
    # upgrade. Start the recorded pre-upgrade instance instead.
    run_bounded "$INIT_DIR/router-policy" start
    run_bounded "$INIT_DIR/router-policy" running
    wait_control_health "${PREINSTALL_ACTIVE_REVISION:-}"
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
    run_bounded "$INIT_DIR/router-policy-watchdog" start
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
  run_bounded env ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" maintenance end >/dev/null 2>&1
}

install_exit() {
  status="$1"
  trap - EXIT
  rollback_status=0
  if [ "$status" -ne 0 ] && [ "${INSTALL_ROLLBACK_ARMED:-0}" = "1" ]; then
    restore_installation || {
      rollback_status=1
      echo "automatic install rollback failed; backup=$BACKUP_DIR" >&2
    }
  fi
  maintenance_status=0
  end_maintenance || {
    maintenance_status=1
    echo "install warning: maintenance lease could not be closed" >&2
  }
  if [ "$status" -eq 0 ] && { [ "$rollback_status" -ne 0 ] || [ "$maintenance_status" -ne 0 ]; }; then
    status=1
  fi
  exit "$status"
}

atomic_copy() {
  source="$1"
  target="$2"
  mode_bits="$3"
  mkdir -p "$(dirname "$target")"
  validate_no_symlink_path "$target" || { echo "refusing symlink install target path: $target" >&2; return 1; }
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
  chmod +x "$staged_prefix/openwrt/ensure-dns-observer.sh"
  chmod +x "$staged_prefix/openwrt/hotplug-event"
  if [ -e "$PREFIX/components" ]; then
    if [ ! -d "$PREFIX/components" ] || [ -L "$PREFIX/components" ]; then
      echo "refusing unsafe managed component runtime: $PREFIX/components" >&2
      return 1
    fi
    component_links=$(find "$PREFIX/components" -type l -print) || return 1
    if [ -n "$component_links" ]; then
      echo "refusing symlink in managed component runtime: $PREFIX/components" >&2
      return 1
    fi
  fi
  [ ! -e "$PREFIX" ] || mv "$PREFIX" "$old_prefix"
  if [ -d "$old_prefix/components" ]; then
    mv "$old_prefix/components" "$staged_prefix/components"
  fi
  mv "$staged_prefix" "$PREFIX"
  rm -rf "$old_prefix"
  atomic_copy "$SOURCE_BINARY" "$ROUTER_POLICY_BIN" 755
  atomic_copy "$SOURCE_HELPER_BINARY" "$ROUTER_POLICY_HELPER_BIN" 755
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
  atomic_copy "$ROOT/openwrt/init.d/router-policy-helper" "$INIT_DIR/router-policy-helper" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy" "$INIT_DIR/router-policy" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-dns-observer" "$INIT_DIR/router-policy-dns-observer" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-boot-guard" "$INIT_DIR/router-policy-boot-guard" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-watchdog" "$INIT_DIR/router-policy-watchdog" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-xray" "$INIT_DIR/router-policy-xray" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-zapret" "$INIT_DIR/router-policy-zapret" 755
  atomic_copy "$ROOT/openwrt/hotplug/iface/95-router-policy" "$HOTPLUG_IFACE_DIR/95-router-policy" 755
  atomic_copy "$ROOT/openwrt/hotplug/firewall/95-router-policy" "$HOTPLUG_FIREWALL_DIR/95-router-policy" 755
}

activate_dns_observer() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  observer="$PREFIX/openwrt/ensure-dns-observer.sh"
  [ -x "$observer" ] || {
    echo "install blocked: DNS observation bootstrap helper is unavailable" >&2
    return 1
  }
  "$observer" --reload-if-needed
}

dry_run() {
  detect
  echo "would_backup=$BACKUP_DIR"
  echo "would_install_prefix=$PREFIX"
  echo "would_install_config=$ETC_DIR/config/default.json"
  echo "would_install_services=router-policy-dns-observer router-policy-boot-guard router-policy-helper router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
  echo "would_not_enable_services_without=--enable-services"
  echo "would_not_activate_without=--activate --yes"
  echo "would_install_zapret_calibration_runner=$PREFIX/scripts/calibrate-zapret.sh"
  echo "would_install_zapret_quick_runner=$PREFIX/scripts/quick-zapret-check.sh"
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
    begin_maintenance
    stop_control_services_for_upgrade
    snapshot_state_database
    backup
    install_files
    if [ "$enable_services" = "1" ]; then
      activate_dns_observer
    fi
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" validate-config
    "$ROUTER_POLICY_BIN" backup register --root "$BACKUP_DIR" --operation "$(basename "$BACKUP_DIR")" --version "$ROUTER_POLICY_VERSION" --reason install --retention-class installer-fallback >/dev/null
    "$ROUTER_POLICY_BIN" backup prune --root "$BACKUP_ROOT" --max 2 --max-bytes 134217728 --apply >/dev/null
    echo "== setup token =="
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" auth setup-token --if-needed
    restart_running_services
    if [ "$enable_services" = "1" ]; then
      run_bounded "$INIT_DIR/router-policy-dns-observer" enable
      run_bounded "$INIT_DIR/router-policy-boot-guard" enable
      run_bounded "$INIT_DIR/router-policy" enable
      run_bounded "$INIT_DIR/router-policy-watchdog" enable
      start_control_services
      echo "services_enabled=router-policy-dns-observer router-policy-boot-guard router-policy router-policy-watchdog"
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
