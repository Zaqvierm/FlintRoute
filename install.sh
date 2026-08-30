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
UCI_BIN="${UCI_BIN:-uci}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
DF_BIN="${DF_BIN:-df}"
DU_BIN="${DU_BIN:-du}"
SERVICES="router-policy-helper router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
ENABLE_SERVICES="router-policy-dns-observer router-policy-boot-guard $SERVICES"
INSTALL_TARGETS="$PREFIX $ROUTER_POLICY_BIN $ROUTER_POLICY_HELPER_BIN $INIT_DIR/router-policy-helper $INIT_DIR/router-policy $INIT_DIR/router-policy-dns-observer $INIT_DIR/router-policy-boot-guard $INIT_DIR/router-policy-watchdog $INIT_DIR/router-policy-xray $INIT_DIR/router-policy-zapret $HOTPLUG_IFACE_DIR/95-router-policy $HOTPLUG_FIREWALL_DIR/95-router-policy $ETC_DIR/config/default.json $ETC_DIR/config/factory-default.json $ETC_DIR/config/schema.json $ETC_DIR/config/listener.conf $ETC_DIR/helper.env $ETC_DIR/secrets/vpn-subscription-url $ETC_DIR/secrets/vpn-subscription-url.hwid.json $ETC_DIR/secrets/happ-crypt4-private-key.pem $ETC_DIR/secrets/telegram.json $ETC_DIR/secrets/webhook.env $ETC_DIR/secrets $DNSMASQ_DIR/router-policy.conf $STATE_DIR/last-backup-path $STATE_DIR/auth/setup-token.json"

PREFIX_SWITCH_MARKER="$STATE_DIR/prefix-switch.env"
MANAGED_FILE_MANIFEST="$PREFIX/.managed-files.manifest"

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

refresh_install_targets() {
  # dnsmasq may use a platform-specific confdir.  Snapshot the exact observer
  # file that this install can create instead of assuming one filesystem path.
  detected_confdir=""
  if [ -z "$SYSTEM_ROOT" ] && command -v "$UCI_BIN" >/dev/null 2>&1; then
    detected_confdir="$($UCI_BIN -q get 'dhcp.@dnsmasq[0].confdir' 2>/dev/null || true)"
  fi
  if [ -n "$detected_confdir" ]; then
    validate_dnsmasq_confdir "$detected_confdir" || return 1
    DNSMASQ_DIR="$detected_confdir"
  fi
  validate_dnsmasq_confdir "$DNSMASQ_DIR" || return 1
  observer_target="$DNSMASQ_DIR/router-policy.conf"
  case " $INSTALL_TARGETS " in
    *" $observer_target "*) ;;
    *) INSTALL_TARGETS="$INSTALL_TARGETS $observer_target" ;;
  esac
  # The production runtime maps /tmp/router-policy to dnsmasq's jail-owned
  # log path.  Snapshot that exact object too; taking only the controller's
  # generic runtime path would leave the active writer outside rollback.
  if [ "$RUNTIME_DIR" = "$SYSTEM_ROOT/tmp/router-policy" ]; then
    observer_dir="$SYSTEM_ROOT/var/run/dnsmasq"
    # OpenWrt commonly exposes /var -> /tmp.  Snapshot the canonical runtime
    # object so the exact-target ownership validator does not reject this
    # known platform layout as an arbitrary symlink traversal.
    if [ -d "$observer_dir" ]; then
      if command -v readlink >/dev/null 2>&1; then
        canonical_observer_dir="$(readlink -f "$observer_dir" 2>/dev/null)" || {
          echo "install blocked: cannot resolve dnsmasq observer runtime path" >&2
          return 1
        }
        [ -n "$canonical_observer_dir" ] || {
          echo "install blocked: dnsmasq observer runtime path resolved empty" >&2
          return 1
        }
        observation_target="$canonical_observer_dir/router-policy-observations.log"
      else
        echo "install blocked: readlink is required to resolve dnsmasq observer runtime path" >&2
        return 1
      fi
    else
      observation_target="$observer_dir/router-policy-observations.log"
    fi
  else
    observation_target="$RUNTIME_DIR/dns-observations.log"
  fi
  case " $INSTALL_TARGETS " in
    *" $observation_target "*) ;;
    *) INSTALL_TARGETS="$INSTALL_TARGETS $observation_target" ;;
  esac
}

path_size_kb() {
  size_path="$1"
  [ -e "$size_path" ] || { echo 0; return 0; }
  "$DU_BIN" -sk "$size_path" 2>/dev/null | awk 'NR == 1 {print $1 + 0}'
}

preflight_disk_space() {
  filesystem_path="$PREFIX"
  [ -e "$filesystem_path" ] || filesystem_path="$(dirname "$PREFIX")"
  available_kb="$($DF_BIN -Pk "$filesystem_path" 2>/dev/null | awk 'NR == 2 {print $4 + 0}')"
  case "$available_kb" in
    ''|*[!0-9]*) echo "install blocked: unable to determine free disk space" >&2; return 1 ;;
  esac
  existing_kb=0
  for size_path in "$PREFIX" "$BACKUP_ROOT" "$ETC_DIR"; do
    size_value="$(path_size_kb "$size_path")"
    case "$size_value" in
      ''|*[!0-9]*) echo "install blocked: unable to size $size_path" >&2; return 1 ;;
    esac
    existing_kb=$((existing_kb + size_value))
  done
  source_kb=0
  for size_path in "$SOURCE_BINARY" "$SOURCE_HELPER_BINARY" "$ROOT/scripts" "$ROOT/openwrt"; do
    size_value="$(path_size_kb "$size_path")"
    case "$size_value" in
      ''|*[!0-9]*) echo "install blocked: unable to size install source $size_path" >&2; return 1 ;;
    esac
    source_kb=$((source_kb + size_value))
  done
  # Snapshot + export backup + staged prefix + old prefix can coexist.  Keep a
  # fixed 64 MiB cushion for filesystem metadata and OpenWrt overlay churn.
  required_kb=$((existing_kb * 2 + source_kb * 2 + 65536))
  [ "$available_kb" -ge "$required_kb" ] || {
    echo "install blocked: insufficient free space available_kb=$available_kb required_kb=$required_kb" >&2
    return 1
  }
  echo "disk_preflight=ok available_kb=$available_kb required_kb=$required_kb"
}

preflight_install() {
  refresh_install_targets
  validate_managed_roots || return 1
  [ -f "$SOURCE_BINARY" ] || { echo "missing $SOURCE_BINARY; run scripts/build-go.sh before install" >&2; return 1; }
  [ -f "$SOURCE_HELPER_BINARY" ] || { echo "missing $SOURCE_HELPER_BINARY; run scripts/build-go.sh before install" >&2; return 1; }
  for p in "$ROOT/scripts" "$ROOT/openwrt" "$ROOT/config/default.json" "$ROOT/config/schema.json" "$ROOT/config/router-policy-helper.env"; do
    [ -e "$p" ] || { echo "missing install source: $p" >&2; return 1; }
  done
  if [ -f "$ROOT/SHA256SUMS" ]; then
    command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required to verify this install bundle" >&2; return 1; }
    (cd "$ROOT" && sha256sum -c SHA256SUMS >/dev/null) || { echo "install bundle checksum verification failed" >&2; return 1; }
  fi
  validate_critical_system_dirs && validate_backup_paths && preflight_disk_space
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

managed_static_paths() {
  printf '%s\n' \
    "$ROUTER_POLICY_BIN" \
    "$ROUTER_POLICY_HELPER_BIN" \
    "$INIT_DIR/router-policy-helper" \
    "$INIT_DIR/router-policy" \
    "$INIT_DIR/router-policy-dns-observer" \
    "$INIT_DIR/router-policy-boot-guard" \
    "$INIT_DIR/router-policy-watchdog" \
    "$INIT_DIR/router-policy-xray" \
    "$INIT_DIR/router-policy-zapret" \
    "$HOTPLUG_IFACE_DIR/95-router-policy" \
    "$HOTPLUG_FIREWALL_DIR/95-router-policy"
}

write_managed_file_manifest() {
  [ -d "$PREFIX" ] && [ ! -L "$PREFIX" ] || {
    echo "install blocked: managed prefix is not a directory" >&2
    return 1
  }
  manifest_tmp="$MANAGED_FILE_MANIFEST.tmp"
  if [ -e "$manifest_tmp" ] || [ -L "$manifest_tmp" ]; then
    echo "install blocked: managed-file manifest temp path already exists" >&2
    return 1
  fi
  : > "$manifest_tmp"
  while IFS= read -r managed_path; do
    [ -n "$managed_path" ] || continue
    [ -f "$managed_path" ] && [ ! -L "$managed_path" ] || {
      echo "install blocked: managed static file is missing or unsafe: $managed_path" >&2
      rm -f "$manifest_tmp"
      return 1
    }
    managed_hash="$(hash_file "$managed_path")" || {
      rm -f "$manifest_tmp"
      return 1
    }
    printf '%s|%s\n' "$managed_path" "$managed_hash" >> "$manifest_tmp"
  done <<EOF
$(managed_static_paths)
EOF
  chmod 600 "$manifest_tmp"
  if [ -z "$SYSTEM_ROOT" ]; then
    chown 0:0 "$manifest_tmp" || {
      rm -f "$manifest_tmp"
      echo "install blocked: cannot assign managed-file manifest ownership" >&2
      return 1
    }
  fi
  mv "$manifest_tmp" "$MANAGED_FILE_MANIFEST"
  sync_file_and_parent "$MANAGED_FILE_MANIFEST"
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

validate_dnsmasq_confdir() {
  candidate_dir="$1"
  # The observer owns one exact fragment in a штатный dnsmasq include
  # directory. Never let a UCI value turn installation into a generic root
  # file writer; custom directories need a reviewed ownership contract.
  case "$candidate_dir" in
    "${SYSTEM_ROOT:-}/tmp/dnsmasq.d"|"${SYSTEM_ROOT:-}/etc/dnsmasq.d") ;;
    *)
      echo "install blocked: dnsmasq confdir is outside the owned allowlist: $candidate_dir" >&2
      return 1
      ;;
  esac
  validate_no_symlink_path "$candidate_dir" || {
    echo "install blocked: unsafe dnsmasq confdir path: $candidate_dir" >&2
    return 1
  }
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

validate_managed_roots() {
  # mkdir -p follows an existing symlink. Re-check every managed root at the
  # mutation boundary so an environment override or path replacement cannot
  # redirect writes into a foreign tree between preflight and install_files.
  for managed_root in \
    "$PREFIX" \
    "$ETC_DIR" \
    "$ETC_DIR/config" \
    "$ETC_DIR/secrets" \
    "$ETC_DIR/xray" \
    "$ETC_DIR/zapret" \
    "$ETC_DIR/firewall" \
    "$STATE_DIR" \
    "$RUNTIME_DIR" \
    "$BIN_DIR" \
    "$INIT_DIR" \
    "$RC_DIR" \
    "$HOTPLUG_IFACE_DIR" \
    "$HOTPLUG_FIREWALL_DIR" \
    "$DNSMASQ_DIR"; do
    [ -n "$managed_root" ] || continue
    validate_no_symlink_path "$managed_root" || {
      echo "install blocked: managed path contains a symlink or unsafe component: $managed_root" >&2
      return 1
    }
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
  # dnsmasq is not a FlintRoute-owned service and is never enabled/disabled
  # by the normal install path.  It is nevertheless recorded as a separate
  # runtime dependency so rollback can restore the state of a dnsmasq restart
  # triggered by observer activation.
  [ "$candidate_service" = "dnsmasq" ] && return 0
  for allowed_service in $ENABLE_SERVICES; do
    [ "$candidate_service" != "$allowed_service" ] || return 0
  done
  return 1
}

path_metadata() {
  target="$1"
  # Prefer stat when the target provides it.  Some supported OpenWrt images
  # omit the stat applet entirely, so the installer must retain a read-only
  # fallback instead of treating an inspectable system as unsafe by accident.
  if command -v stat >/dev/null 2>&1; then
    if metadata_output="$(umask 022; stat -c '%a|%u|%g' "$target" 2>/dev/null)"; then
      printf '%s\n' "$metadata_output"
      return 0
    fi
  fi
  if command -v busybox >/dev/null 2>&1; then
    if metadata_output="$(umask 022; busybox stat -c '%a|%u|%g' "$target" 2>/dev/null)"; then
      printf '%s\n' "$metadata_output"
      return 0
    fi
  fi

  # BusyBox ls -ln exposes numeric uid/gid and the object permission string.
  # Convert the three rwx triplets to the same octal representation returned
  # by stat.  Critical-directory checks only accept ordinary rwx bits; special
  # bits are intentionally rejected rather than guessed.
  perm_digit() {
    case "$1" in
      ---) printf '0' ;; --x) printf '1' ;; -w-) printf '2' ;; -wx) printf '3' ;;
      r--) printf '4' ;; r-x) printf '5' ;; rw-) printf '6' ;; rwx) printf '7' ;;
      *) return 1 ;;
    esac
  }
  metadata_line="$(LC_ALL=C ls -ldn "$target" 2>/dev/null)" || return 1
  permissions="$(printf '%s\n' "$metadata_line" | awk 'NR == 1 { print substr($1, 2, 9) }')"
  uid="$(printf '%s\n' "$metadata_line" | awk 'NR == 1 { print $3 }')"
  gid="$(printf '%s\n' "$metadata_line" | awk 'NR == 1 { print $4 }')"
  [ "${#permissions}" -eq 9 ] || return 1
  case "$uid:$gid" in *[!0-9:]*|*:|:*) return 1 ;; esac
  owner_bits="$(perm_digit "$(printf '%s' "$permissions" | cut -c1-3)")" || return 1
  group_bits="$(perm_digit "$(printf '%s' "$permissions" | cut -c4-6)")" || return 1
  other_bits="$(perm_digit "$(printf '%s' "$permissions" | cut -c7-9)")" || return 1
  printf '%s%s%s|%s|%s\n' "$owner_bits" "$group_bits" "$other_bits" "$uid" "$gid"
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
      # Overlayfs commonly presents / and /etc as 0755 even when the
      # read-only squashfs lower layer reports 0775.  That pair is a known
      # OpenWrt layout difference, not the permission-loss failure this guard
      # is meant to catch.  All other mismatches remain fail-closed.
      case "$directory_mode:$reference_mode" in
        "$reference_mode:$reference_mode"|755:775) ;;
        *)
        echo "install blocked: critical directory mode differs from ROM: $target mode=$directory_mode rom=$reference_mode" >&2
        return 1
        ;;
      esac
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
    PREINSTALL_ACTIVE_CANDIDATE_HASH="$(health_json_field active_candidate_hash "$RUNTIME_DIR/install-health.json")"
    PREINSTALL_ACTIVE_ARTIFACT_MANIFEST_HASH="$(health_json_field active_artifact_manifest_hash "$RUNTIME_DIR/install-health.json")"
    export PREINSTALL_ACTIVE_REVISION PREINSTALL_ACTIVE_CANDIDATE_HASH PREINSTALL_ACTIVE_ARTIFACT_MANIFEST_HASH
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
  # This archive is an export backup, but keeping only non-directory members
  # makes accidental future restore code unable to replay /etc or /usr modes.
  # Parent directories are created by the restoring filesystem with its own
  # permissions; directory metadata from a 077 staging umask is never carried.
  file_list="$BACKUP_DIR/files.list"
  (cd "$staging" && find . -mindepth 1 ! -type d -print | sed 's#^\./##' > "$file_list") || {
    rm -f "$file_list"
    return 1
  }
  if [ -s "$file_list" ]; then
    (cd "$staging" && "$TAR_BIN" -cf "$archive.tmp" -T "$file_list") || {
      rm -f "$file_list" "$archive.tmp"
      return 1
    }
  else
    # BusyBox tar rejects an empty -T file.  A POSIX tar stream with two
    # zero blocks is a valid empty archive and keeps a clean install's
    # rollback manifest verifiable without archiving synthetic parents.
    dd if=/dev/zero of="$archive.tmp" bs=512 count=2 2>/dev/null || {
      rm -f "$file_list" "$archive.tmp"
      return 1
    }
  fi
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
  refresh_install_targets
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
      metadata=$(path_metadata "$p") || { echo "unable to snapshot metadata: $p" >&2; return 1; }
      target_mode=${metadata%%|*}; ownership=${metadata#*|}; uid=${ownership%%|*}; gid=${ownership#*|}
      echo "present|$p|$target_mode|$uid|$gid" >> "$manifest"
      # The secrets directory is metadata-only.  Recursively copying it would
      # capture foreign children and make rollback delete/recreate resources
      # FlintRoute does not own.  Exact files (including managed secret files)
      # are listed separately below.  Other owned directory targets (notably
      # the code prefix) retain their existing recursive snapshot semantics.
      if [ "$p" != "$ETC_DIR/secrets" ] || [ ! -d "$p" ]; then
        relative="${p#/}"
        mkdir -p "$staging/$(dirname "$relative")"
        copy_preserving_metadata "$p" "$staging/$relative"
      fi
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
  # Observer activation may restart dnsmasq after the file snapshot is taken.
  # Keep its pre-install enabled/running state in the same integrity-checked
  # service manifest, but do not include it in ENABLE_SERVICES: successful
  # installs must not alter an unrelated service's enablement.
  dnsmasq_init="$INIT_DIR/dnsmasq"
  dnsmasq_enabled=0
  dnsmasq_running=0
  if [ -z "$SYSTEM_ROOT" ] && [ -x "$dnsmasq_init" ]; then
    run_bounded "$dnsmasq_init" enabled >/dev/null 2>&1 && dnsmasq_enabled=1
    run_bounded "$dnsmasq_init" running >/dev/null 2>&1 && dnsmasq_running=1
  fi
  echo "dnsmasq|$dnsmasq_enabled|$dnsmasq_running" >> "$services"
  # Archive only the exact allowlisted targets recorded in the manifest.  Do
  # not feed find(1) the staging tree: synthetic parents such as usr/ and
  # usr/lib/ inherit umask 077 and must never become archive members, even if
  # restore later extracts into a private directory.
  file_list="$snapshot/files.list"
  : > "$file_list"
  while IFS='|' read -r presence p target_mode uid gid; do
    [ "$presence" = "present" ] || continue
    # The secrets directory entry carries metadata only; its exact managed
    # files are separate archive members.  Other owned directory targets keep
    # recursive archive semantics (for example the active code prefix).
    [ "$p" != "$ETC_DIR/secrets" ] || continue
    relative="${p#/}"
    [ -n "$relative" ] || { rm -f "$file_list"; return 1; }
    printf '%s\n' "$relative" >> "$file_list"
  done < "$manifest"
  if [ -s "$file_list" ]; then
    (cd "$staging" && "$TAR_BIN" -cf "$archive.tmp" -T "$file_list") || {
      rm -f "$file_list" "$archive.tmp"
      return 1
    }
  else
    # BusyBox tar rejects an empty -T file.  A POSIX tar stream with two
    # zero blocks is a valid empty archive and keeps a clean install's
    # rollback manifest verifiable without archiving synthetic parents.
    dd if=/dev/zero of="$archive.tmp" bs=512 count=2 2>/dev/null || {
      rm -f "$file_list" "$archive.tmp"
      return 1
    }
  fi
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
    # Stop the non-root controller before the privileged helper so rollback
    # cannot restore a mixed binary/config generation underneath a live peer.
    for service in router-policy-watchdog router-policy router-policy-helper; do
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
    if [ "$p" = "$ETC_DIR/secrets" ]; then
      # The secrets directory itself is an owned container, but its children
      # are not all FlintRoute-owned. Restore only the container metadata and
      # exact managed secret entries; never recursively remove it.
      validate_no_symlink_path "$p" || {
        rm -rf "$restore_staging"
        echo "automatic install rollback blocked: symlink in secrets directory path: $p" >&2
        return 1
      }
      if [ "$presence" = "present" ]; then
        if [ -e "$p" ] && [ ! -d "$p" ]; then
          [ ! -L "$p" ] || {
            rm -rf "$restore_staging"
            echo "automatic install rollback blocked: secrets directory became a symlink" >&2
            return 1
          }
          rm -f "$p" || {
            rm -rf "$restore_staging"
            return 1
          }
        fi
        [ -d "$p" ] || mkdir -p "$p" || {
          rm -rf "$restore_staging"
          return 1
        }
        chmod "$target_mode" "$p" || {
          rm -rf "$restore_staging"
          return 1
        }
        if [ "$(id -u)" = "0" ] && command -v chown >/dev/null 2>&1; then
          chown "$uid:$gid" "$p" || {
            rm -rf "$restore_staging"
            return 1
          }
        fi
      else
        if [ -d "$p" ]; then
          # Managed secret-file entries are processed before this directory
          # entry. A non-empty directory therefore contains an unowned file;
          # refuse to delete it instead of using rm -rf.
          rmdir "$p" || {
            rm -rf "$restore_staging"
            echo "automatic install rollback blocked: secrets directory contains unowned entries" >&2
            return 1
          }
        elif [ -L "$p" ]; then
          rm -rf "$restore_staging"
          echo "automatic install rollback blocked: refusing to remove foreign secrets symlink" >&2
          return 1
        elif [ -e "$p" ]; then
          rm -rf "$restore_staging"
          echo "automatic install rollback blocked: secrets target changed type" >&2
          return 1
        fi
      fi
      continue
    fi
    if [ -d "$p" ]; then
      # The only recursive install target is the FlintRoute prefix.  Never
      # treat an arbitrary directory from a manifest as owned: validate its
      # bounded prefix shape and every nested object before removing it.
      case "$p" in
        "$PREFIX")
          remove_owned_prefix_switch_tree "$p" || {
            rm -rf "$restore_staging"
            echo "automatic install rollback blocked: prefix ownership is unproven: $p" >&2
            return 1
          }
          ;;
        *)
          rm -rf "$restore_staging"
          echo "automatic install rollback blocked: recursive target is not the owned prefix: $p" >&2
          return 1
          ;;
      esac
    elif [ -L "$p" ]; then
      rm -rf "$restore_staging"
      echo "automatic install rollback blocked: refusing to remove symlink target: $p" >&2
      return 1
    elif [ -e "$p" ]; then
      rm -f "$p" || {
        rm -rf "$restore_staging"
        echo "automatic install rollback blocked: target could not be removed: $p" >&2
        return 1
      }
    fi
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
      if [ ! -x "$init" ]; then
        [ "$service" = "dnsmasq" ] && service_restore_ok=0
        continue
      fi
      if [ "$enabled" = "1" ]; then
        run_bounded "$init" enable >/dev/null 2>&1 || service_restore_ok=0
      else
        run_bounded "$init" disable >/dev/null 2>&1 || service_restore_ok=0
      fi
      if [ "$service" = "dnsmasq" ]; then
        if [ "$running" = "1" ]; then
          run_bounded "$init" start >/dev/null 2>&1 || service_restore_ok=0
          [ "$service_restore_ok" != "1" ] || run_bounded "$init" running >/dev/null 2>&1 || service_restore_ok=0
        else
          run_bounded "$init" stop >/dev/null 2>&1 || service_restore_ok=0
          [ "$service_restore_ok" != "1" ] || wait_service_stopped "$init" || service_restore_ok=0
        fi
      fi
    done < "$services"
    if [ "$service_restore_ok" = "1" ] && service_was_running router-policy-helper; then
      run_bounded "$INIT_DIR/router-policy-helper" start >/dev/null 2>&1 || service_restore_ok=0
      [ "$service_restore_ok" != "1" ] || run_bounded "$INIT_DIR/router-policy-helper" running >/dev/null 2>&1 || service_restore_ok=0
    fi
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
  clear_prefix_switch_marker || {
    echo "automatic install rollback unavailable: prefix switch marker could not be cleared" >&2
    return 1
  }
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
  health_parser_bin="$ROUTER_POLICY_BIN"
  # Parse with the candidate binary when available.  This keeps upgrades from
  # depending on an older controller that predates the typed parser, while
  # still failing closed if neither side can provide the command.
  if [ -x "$SOURCE_BINARY" ]; then
    health_parser_bin="$SOURCE_BINARY"
  fi
  [ -x "$health_parser_bin" ] || {
    echo "install blocked: typed health parser is unavailable: $ROUTER_POLICY_BIN" >&2
    return 1
  }
  run_bounded "$health_parser_bin" internal-health-field --path "$file" --field "$field"
}

resolve_control_health_url() {
  # The controller may be intentionally exposed on a private LAN address.
  # Never accept an arbitrary URL here: installer health checks must stay on
  # the local router and must follow the same owned listener configuration as
  # the init script.  The test-only SYSTEM_ROOT path is accepted without an
  # address lookup because it has no real network namespace.
  health_host="127.0.0.1"
  health_port="8787"
  listener_config="$ETC_DIR/config/listener.conf"
  if [ -f "$listener_config" ] && [ ! -L "$listener_config" ]; then
    configured_listener="$(sed -n 's/^listen_address=//p' "$listener_config" | head -n 1)"
    if [ -n "$configured_listener" ]; then
      case "$configured_listener" in
        *:*:*|*/*|*\ *|*[!A-Za-z0-9.:-]*)
          echo "install blocked: invalid controller listener address in $listener_config" >&2
          return 1
          ;;
        *:*)
          health_host="${configured_listener%:*}"
          health_port="${configured_listener##*:}"
          ;;
        *)
          echo "install blocked: controller listener has no port in $listener_config" >&2
          return 1
          ;;
      esac
    fi
  fi
  case "$health_host" in
    127.0.0.1)
      ;;
    ''|0.0.0.0|::|\[::*\]|*.*.*.*.*|*[!0-9.]*)
      echo "install blocked: controller health listener is not a supported local IPv4 address: $health_host" >&2
      return 1
      ;;
    *)
      if [ -z "$SYSTEM_ROOT" ]; then
        command -v ip >/dev/null 2>&1 || {
          echo "install blocked: ip is required to verify the controller listener address" >&2
          return 1
        }
        if ! ip -4 addr show 2>/dev/null | awk -v wanted="$health_host" '$1 == "inet" {sub("/.*", "", $2); if ($2 == wanted) found=1} END {exit(found ? 0 : 1)}'; then
          echo "install blocked: controller listener address is not assigned locally: $health_host" >&2
          return 1
        fi
      fi
      ;;
  esac
  case "$health_port" in
    ''|*[!0-9]*)
      echo "install blocked: invalid controller listener port: $health_port" >&2
      return 1
      ;;
  esac
  [ "$health_port" -ge 1 ] 2>/dev/null && [ "$health_port" -le 65535 ] 2>/dev/null || {
    echo "install blocked: controller listener port out of range: $health_port" >&2
    return 1
  }
  printf 'http://%s:%s/api/v1/health\n' "$health_host" "$health_port"
}

valid_health_hash() {
  value="$1"
  printf '%s\n' "$value" | grep -Eq '^sha256:[0-9a-fA-F]{64}$'
}

wait_control_health() {
  expected_revision="${1:-}"
  expected_candidate_hash="${2:-${PREINSTALL_ACTIVE_CANDIDATE_HASH:-}}"
  expected_artifact_hash="${3:-${PREINSTALL_ACTIVE_ARTIFACT_MANIFEST_HASH:-}}"
  max_attempts="${ROUTER_POLICY_HEALTH_ATTEMPTS:-120}"
  case "$max_attempts" in *[!0-9]*|'') max_attempts=120 ;; esac
  [ "$max_attempts" -ge 1 ] && [ "$max_attempts" -le 120 ] || max_attempts=120
  command -v wget >/dev/null 2>&1 || { echo "wget is required to verify the control plane" >&2; return 1; }
  health_url="$(resolve_control_health_url)" || return 1
  attempt=0
  while [ "$attempt" -lt "$max_attempts" ]; do
    if wget -q -O "$RUNTIME_DIR/install-health.json" "$health_url"; then
      health_status="$(health_json_field status "$RUNTIME_DIR/install-health.json")"
      recovery_status="$(health_json_field recovery_status "$RUNTIME_DIR/install-health.json")"
      recovery_commit_phase="$(health_json_field recovery_commit_phase "$RUNTIME_DIR/install-health.json")"
      active_revision="$(health_json_field active_revision "$RUNTIME_DIR/install-health.json")"
      active_candidate_hash="$(health_json_field active_candidate_hash "$RUNTIME_DIR/install-health.json")"
      active_artifact_hash="$(health_json_field active_artifact_manifest_hash "$RUNTIME_DIR/install-health.json")"
      recovery_safe=0
      case "$recovery_status:$recovery_commit_phase" in
        ok:*) recovery_safe=1 ;;
        not_required:baseline_confirmed) recovery_safe=1 ;;
      esac
      hash_binding_ok=0
      if valid_health_hash "$active_candidate_hash" && { [ -z "$expected_candidate_hash" ] || [ "$active_candidate_hash" = "$expected_candidate_hash" ]; }; then
        case "$recovery_status:$recovery_commit_phase:$active_artifact_hash" in
          not_required:baseline_confirmed:) hash_binding_ok=1 ;;
          ok:*:*)
            if valid_health_hash "$active_artifact_hash" && { [ -z "$expected_artifact_hash" ] || [ "$active_artifact_hash" = "$expected_artifact_hash" ]; }; then
              hash_binding_ok=1
            fi
            ;;
        esac
      fi
      if [ "$health_status" = "ok" ] && [ "$recovery_safe" = "1" ] && [ -n "$active_revision" ] && [ "$hash_binding_ok" = "1" ] && { [ -z "$expected_revision" ] || [ "$active_revision" = "$expected_revision" ]; }; then
        echo "control_plane_health=ok"
        echo "control_plane_active_revision=$active_revision"
        echo "control_plane_candidate_hash=$active_candidate_hash"
        [ -z "$active_artifact_hash" ] || echo "control_plane_artifact_manifest_hash=$active_artifact_hash"
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
  # Stop the controller before its privileged helper.  Replacing helper
  # artifacts while the old process is serving requests would leave a mixed
  # generation; a fresh controller must never race an old helper.
  for service in router-policy-watchdog router-policy router-policy-helper; do
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
    # A production controller is only valid with the pinned helper peer.  Do
    # not resurrect the controller against a missing/stopped helper after an
    # upgrade; that would turn a safe install into a root/direct-mutation
    # fallback instead of failing closed.
    if ! service_was_running router-policy-helper; then
      echo "install blocked: controller was running without its helper service" >&2
      return 1
    fi
    run_bounded "$INIT_DIR/router-policy-helper" start
    run_bounded "$INIT_DIR/router-policy-helper" running
  fi
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
  # The helper is the dependency boundary: it must be running before the
  # non-root controller is started.  Starting the controller first creates a
  # deterministic health failure on a clean install.
  for service in router-policy-helper router-policy router-policy-watchdog; do
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
  # Synthetic roots used by local fault fixtures do not represent a power-loss
  # boundary.  Avoid flushing the host filesystem for every copied file; real
  # OpenWrt installs keep the durable sync below.
  if [ -z "$SYSTEM_ROOT" ]; then
    if ! sync -f "$(dirname "$target")" 2>/dev/null; then
      # BusyBox implementations may not support sync -f.  A global sync is a
      # valid fallback, but a failed fallback is a durability failure, not a
      # warning we can hide: the caller must abort before reporting success.
      if ! sync 2>/dev/null; then
        echo "install failed: unable to durably sync target directory: $target" >&2
        return 1
      fi
    fi
  fi
}

sync_file_and_parent() {
  sync_target="$1"
  [ -n "$SYSTEM_ROOT" ] && return 0
  if sync -f "$sync_target" 2>/dev/null; then
    sync -f "$(dirname "$sync_target")" 2>/dev/null || sync
  else
    sync
  fi
}

durable_rename() {
  rename_source="$1"
  rename_target="$2"
  mv "$rename_source" "$rename_target" || return 1
  # A successful rename is not durable until the containing directory is
  # flushed.  This closes the power-loss window between prefix moves; the
  # durable marker still records the phase for restart recovery.
  sync_file_and_parent "$(dirname "$rename_target")"
}

write_prefix_switch_marker() {
  switch_phase="$1"
  switch_staged="$2"
  switch_old="$3"
  case "$switch_staged" in "$PREFIX.install."*) ;; *) echo "install blocked: invalid staged prefix path" >&2; return 1 ;; esac
  case "$switch_old" in "$PREFIX.old."*) ;; *) echo "install blocked: invalid old prefix path" >&2; return 1 ;; esac
  mkdir -p "$STATE_DIR"
  {
    echo "version=1"
    echo "phase=$switch_phase"
    echo "prefix=$PREFIX"
    echo "staged=$switch_staged"
    echo "old=$switch_old"
  } > "$PREFIX_SWITCH_MARKER.tmp"
  chmod 600 "$PREFIX_SWITCH_MARKER.tmp"
  mv "$PREFIX_SWITCH_MARKER.tmp" "$PREFIX_SWITCH_MARKER"
  sync_file_and_parent "$PREFIX_SWITCH_MARKER"
}

clear_prefix_switch_marker() {
  rm -f "$PREFIX_SWITCH_MARKER"
  [ ! -e "$PREFIX_SWITCH_MARKER" ] || return 1
}

prefix_switch_top_entry_allowed() {
  case "$1" in
    scripts|openwrt|components|.managed-files.manifest) return 0 ;;
    *) return 1 ;;
  esac
}

remove_owned_prefix_switch_tree() {
  cleanup_tree="$1"
  [ -e "$cleanup_tree" ] || [ -L "$cleanup_tree" ] || return 0
  case "$cleanup_tree" in
    "$PREFIX"|"$PREFIX.install."*|"$PREFIX.old."*) ;;
    *)
      echo "install blocked: invalid prefix switch cleanup path: $cleanup_tree" >&2
      return 1
      ;;
  esac
  [ -d "$cleanup_tree" ] && [ ! -L "$cleanup_tree" ] || {
    echo "install blocked: prefix switch cleanup target is not an owned directory: $cleanup_tree" >&2
    return 1
  }
  command -v find >/dev/null 2>&1 || {
    echo "install blocked: find is required to validate prefix switch cleanup" >&2
    return 1
  }
  for entry in "$cleanup_tree"/* "$cleanup_tree"/.[!.]* "$cleanup_tree"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    cleanup_name="${entry##*/}"
    prefix_switch_top_entry_allowed "$cleanup_name" || {
      echo "install blocked: unowned prefix switch entry: $entry" >&2
      return 1
    }
    case "$cleanup_name" in
      .managed-files.manifest)
        [ -f "$entry" ] && [ ! -L "$entry" ] || {
          echo "install blocked: prefix switch manifest is not regular" >&2
          return 1
        }
        ;;
      scripts|openwrt|components)
        [ -d "$entry" ] && [ ! -L "$entry" ] || {
          echo "install blocked: prefix switch tree is not a directory: $entry" >&2
          return 1
        }
        # BusyBox find on OpenWrt does not implement GNU's `-quit`. Capture
        # the bounded result and inspect its first line instead; the command
        # status is still checked so an unsupported/failed traversal fences
        # cleanup rather than silently accepting an unverified tree.
        if ! cleanup_unsafe_all="$(find "$entry" \( -type l -o ! -type f -a ! -type d \) -print 2>/dev/null)"; then
          echo "install blocked: could not validate prefix switch entry: $entry" >&2
          return 1
        fi
        cleanup_unsafe="$(printf '%s\n' "$cleanup_unsafe_all" | head -n 1)"
        [ -z "$cleanup_unsafe" ] || {
          echo "install blocked: unsafe prefix switch entry: $cleanup_unsafe" >&2
          return 1
        }
        ;;
    esac
  done
  cleanup_list="$STATE_DIR/prefix-cleanup.$$"
  [ ! -e "$cleanup_list" ] && [ ! -L "$cleanup_list" ] || {
    echo "install blocked: prefix cleanup list already exists: $cleanup_list" >&2
    return 1
  }
  if ! find "$cleanup_tree" -depth -print > "$cleanup_list"; then
    rm -f "$cleanup_list"
    echo "install blocked: could not enumerate prefix switch cleanup: $cleanup_tree" >&2
    return 1
  fi
  cleanup_failed=0
  while IFS= read -r entry; do
    [ "$entry" != "$cleanup_tree" ] || continue
    if [ -d "$entry" ] && [ ! -L "$entry" ]; then
      rmdir "$entry" || cleanup_failed=1
    else
      rm -f "$entry" || cleanup_failed=1
    fi
  done < "$cleanup_list"
  rm -f "$cleanup_list"
  if [ "$cleanup_failed" -ne 0 ]; then
    echo "install blocked: could not remove owned prefix switch tree: $cleanup_tree" >&2
    return 1
  fi
  rmdir "$cleanup_tree" || {
    echo "install blocked: prefix switch cleanup tree is not empty: $cleanup_tree" >&2
    return 1
  }
}

recover_prefix_switch() {
  [ -f "$PREFIX_SWITCH_MARKER" ] || return 0
  marker_version="$(sed -n 's/^version=//p' "$PREFIX_SWITCH_MARKER" | head -n 1)"
  marker_prefix="$(sed -n 's/^prefix=//p' "$PREFIX_SWITCH_MARKER" | head -n 1)"
  marker_phase="$(sed -n 's/^phase=//p' "$PREFIX_SWITCH_MARKER" | head -n 1)"
  marker_staged="$(sed -n 's/^staged=//p' "$PREFIX_SWITCH_MARKER" | head -n 1)"
  marker_old="$(sed -n 's/^old=//p' "$PREFIX_SWITCH_MARKER" | head -n 1)"
  [ "$marker_version" = "1" ] && [ "$marker_prefix" = "$PREFIX" ] || {
    echo "install blocked: invalid durable prefix switch marker" >&2
    return 1
  }
  case "$marker_staged" in "$PREFIX.install."*) ;; *) echo "install blocked: invalid durable staged prefix marker" >&2; return 1 ;; esac
  case "$marker_old" in "$PREFIX.old."*) ;; *) echo "install blocked: invalid durable old prefix marker" >&2; return 1 ;; esac
  case "$marker_phase" in
    prepared)
      if [ -e "$PREFIX" ] && [ ! -e "$marker_old" ]; then
        remove_owned_prefix_switch_tree "$marker_staged"
      elif [ ! -e "$PREFIX" ] && [ -e "$marker_old" ] && [ -e "$marker_staged" ]; then
        durable_rename "$marker_staged" "$PREFIX"
      else
        echo "install blocked: prefix switch marker has ambiguous prepared state" >&2
        return 1
      fi
      ;;
    old_moved)
      if [ ! -e "$PREFIX" ] && [ -e "$marker_staged" ]; then
        durable_rename "$marker_staged" "$PREFIX"
      elif [ ! -e "$PREFIX" ] && [ ! -e "$marker_staged" ] && [ -e "$marker_old" ]; then
        durable_rename "$marker_old" "$PREFIX"
      elif [ -e "$PREFIX" ] && [ ! -e "$marker_staged" ] && [ -e "$marker_old" ]; then
        # Legacy v1 marker: an older installer could persist old_moved and
        # lose power immediately after the final staged->prefix rename. The
        # atomic directory rename leaves the new prefix and old backup; keep
        # the active prefix and continue recovery instead of fencing a safe
        # completed switch.
        :
      else
        echo "install blocked: prefix switch marker has ambiguous old_moved state" >&2
        return 1
      fi
      ;;
    ready_to_activate)
      # This phase is persisted before the final rename. Therefore a restart
      # can distinguish both sides of the rename without guessing: either the
      # staged tree is still present (perform the rename), or the active tree
      # is present and the rename already committed.
      if [ ! -e "$PREFIX" ] && [ -e "$marker_staged" ] && [ -e "$marker_old" ]; then
        durable_rename "$marker_staged" "$PREFIX"
      elif [ -e "$PREFIX" ] && [ ! -e "$marker_staged" ] && [ -e "$marker_old" ]; then
        :
      else
        echo "install blocked: prefix switch marker has ambiguous ready_to_activate state" >&2
        return 1
      fi
      ;;
    new_active)
      [ -e "$PREFIX" ] || {
        echo "install blocked: durable prefix marker says new generation is active but prefix is missing" >&2
        return 1
      }
      remove_owned_prefix_switch_tree "$marker_staged"
      ;;
    *)
      echo "install blocked: unknown durable prefix switch phase" >&2
      return 1
      ;;
  esac
  sync_file_and_parent "$(dirname "$PREFIX")"
  clear_prefix_switch_marker
}

finalize_prefix_switch() {
  if [ -n "${old_prefix:-}" ]; then
    case "$old_prefix" in "$PREFIX.old."*) ;; *) echo "install blocked: refusing unknown old prefix cleanup" >&2; return 1 ;; esac
    # The previous generation is an owned prefix, but its path alone is not
    # proof that every child is owned. Reuse the same bounded shape/type
    # validation as crash recovery; never recursively delete an injected or
    # foreign top-level entry.
    remove_owned_prefix_switch_tree "$old_prefix" || return 1
  fi
  clear_prefix_switch_marker
}

install_files() {
  recover_prefix_switch
  # Re-check the secrets path immediately before mkdir/copy operations.  The
  # preflight snapshot rejects symlinks too, but this local guard closes the
  # TOCTOU window where a replaced directory could otherwise redirect the
  # first subscription-file write into a foreign tree.
  validate_managed_roots || return 1
  validate_no_symlink_path "$ETC_DIR/secrets" || {
    echo "install blocked: secrets path contains a symlink" >&2
    return 1
  }
  validate_managed_secret_paths || return 1
  mkdir -p "$(dirname "$PREFIX")" "$ETC_DIR/config" "$ETC_DIR/secrets" "$ETC_DIR/xray" "$ETC_DIR/zapret" "$ETC_DIR/firewall" "$STATE_DIR/last-good" "$RUNTIME_DIR" "$BIN_DIR" "$INIT_DIR" "$RC_DIR" "$HOTPLUG_IFACE_DIR" "$HOTPLUG_FIREWALL_DIR" "$DNSMASQ_DIR"
  staged_prefix="$PREFIX.install.$$"
  old_prefix="$PREFIX.old.$$"
  if [ -e "$staged_prefix" ] || [ -L "$staged_prefix" ] || [ -e "$old_prefix" ] || [ -L "$old_prefix" ]; then
    echo "install blocked: untracked prefix switch path already exists" >&2
    return 1
  fi
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
  write_prefix_switch_marker prepared "$staged_prefix" "$old_prefix"
  if [ -e "$PREFIX" ]; then
    durable_rename "$PREFIX" "$old_prefix"
    write_prefix_switch_marker old_moved "$staged_prefix" "$old_prefix"
  fi
  if [ -d "$old_prefix/components" ]; then
    durable_rename "$old_prefix/components" "$staged_prefix/components"
  fi
  # Persist a phase before the final directory rename. If power is lost after
  # the rename but before new_active is written, recovery can still identify
  # the committed side deterministically.
  write_prefix_switch_marker ready_to_activate "$staged_prefix" "$old_prefix"
  durable_rename "$staged_prefix" "$PREFIX"
  write_prefix_switch_marker new_active "$staged_prefix" "$old_prefix"
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
  if [ -L "$ETC_DIR/helper.env" ]; then
    echo "refusing symlink helper environment: $ETC_DIR/helper.env" >&2
    return 1
  fi
  atomic_copy "$ROOT/config/router-policy-helper.env" "$ETC_DIR/helper.env" 600
  if [ ! -f "$ETC_DIR/secrets/vpn-subscription-url" ]; then
    : > "$ETC_DIR/secrets/vpn-subscription-url"
  fi
  chmod 700 "$ETC_DIR/secrets"
  # Only the explicitly owned subscription file is normalized.  Other files
  # in this directory may belong to an operator or another package and are
  # covered by the directory snapshot without being rewritten.
  chmod 600 "$ETC_DIR/secrets/vpn-subscription-url"
  atomic_copy "$ROOT/openwrt/init.d/router-policy-helper" "$INIT_DIR/router-policy-helper" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy" "$INIT_DIR/router-policy" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-dns-observer" "$INIT_DIR/router-policy-dns-observer" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-boot-guard" "$INIT_DIR/router-policy-boot-guard" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-watchdog" "$INIT_DIR/router-policy-watchdog" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-xray" "$INIT_DIR/router-policy-xray" 755
  atomic_copy "$ROOT/openwrt/init.d/router-policy-zapret" "$INIT_DIR/router-policy-zapret" 755
  atomic_copy "$ROOT/openwrt/hotplug/iface/95-router-policy" "$HOTPLUG_IFACE_DIR/95-router-policy" 755
  atomic_copy "$ROOT/openwrt/hotplug/firewall/95-router-policy" "$HOTPLUG_FIREWALL_DIR/95-router-policy" 755
  write_managed_file_manifest
}

prepare_controller_identity() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  command -v id >/dev/null 2>&1 || { echo "install blocked: id is required for controller identity" >&2; return 1; }
  controller_uid="$(id -u daemon 2>/dev/null)" || {
    echo "install blocked: OpenWrt daemon account is unavailable" >&2
    return 1
  }
  controller_gid="$(id -g daemon 2>/dev/null)" || {
    echo "install blocked: OpenWrt daemon group is unavailable" >&2
    return 1
  }
  [ "$controller_uid" = 1 ] || {
    echo "install blocked: daemon UID is not the pinned helper peer UID: $controller_uid" >&2
    return 1
  }
  command -v chown >/dev/null 2>&1 || { echo "install blocked: chown is required for non-root controller" >&2; return 1; }
  # These roots are FlintRoute-owned, but their contents may survive an
  # upgrade. Never use chown -R here: it would silently take ownership of a
  # nested operator/foreign file. Validate every existing entry first, then
  # assign ownership entry-by-entry. Root-owned entries are accepted as
  # migration input; any other owner fences the install instead of being
  # silently rewritten.
  chown_owned_tree() {
    owned_root="$1"
    [ -e "$owned_root" ] || return 0
    [ -d "$owned_root" ] && [ ! -L "$owned_root" ] || {
      echo "install blocked: owned root is not a directory: $owned_root" >&2
      return 1
    }
    command -v find >/dev/null 2>&1 || {
      echo "install blocked: find is required to validate owned paths: $owned_root" >&2
      return 1
    }
    ownership_list="$RUNTIME_DIR/.ownership-check.$$"
    find "$owned_root" -print > "$ownership_list" || {
      rm -f "$ownership_list"
      echo "install blocked: cannot enumerate controller-owned paths: $owned_root" >&2
      return 1
    }
    ownership_error=""
    while IFS= read -r owned_entry; do
      [ -n "$owned_entry" ] || continue
      if [ -L "$owned_entry" ]; then
        ownership_error="symlink in controller-owned tree: $owned_entry"
        break
      fi
      if ! metadata="$(path_metadata "$owned_entry")"; then
        ownership_error="cannot inspect controller-owned path: $owned_entry"
        break
      fi
      ownership="${metadata#*|}"
      entry_uid="${ownership%%|*}"
      entry_gid="${ownership#*|}"
      case "$entry_uid:$entry_gid" in
        "0:0"|"$controller_uid:$controller_gid") ;;
        *)
          ownership_error="foreign owner in controller-owned tree: $owned_entry uid=$entry_uid gid=$entry_gid"
          break
          ;;
      esac
    done < "$ownership_list"
    if [ -n "$ownership_error" ]; then
      rm -f "$ownership_list"
      echo "install blocked: $ownership_error" >&2
      return 1
    fi
    ownership_error=""
    while IFS= read -r owned_entry; do
      [ -n "$owned_entry" ] || continue
      if ! chown "$controller_uid:$controller_gid" "$owned_entry"; then
        ownership_error="cannot assign controller-owned path: $owned_entry"
        break
      fi
    done < "$ownership_list"
    rm -f "$ownership_list" || {
      echo "install blocked: cannot remove ownership validation artifact: $ownership_list" >&2
      return 1
    }
    [ -z "$ownership_error" ] || {
      echo "install blocked: $ownership_error" >&2
      return 1
    }
  }
  for owned_root in "$ETC_DIR/config" "$STATE_DIR" "$RUNTIME_DIR"; do
    chown_owned_tree "$owned_root" || return 1
  done
  # The controller runs as daemon and must be able to traverse its
  # configuration root.  install_files() creates this directory under the
  # installer's umask, so normalize only this exact FlintRoute-owned
  # container.  Keep it root-owned; the daemon group gets traversal while
  # secret/config permissions remain enforced below.
  chown "0:$controller_gid" "$ETC_DIR" || {
    echo "install blocked: cannot assign controller config root" >&2
    return 1
  }
  chmod 750 "$ETC_DIR" || {
    echo "install blocked: cannot make controller config root traversable" >&2
    return 1
  }
  # Adaptive Zapret metadata is read by the non-root controller and may be
  # refreshed by its bounded calibration runner.  Normalize only this exact
  # owned directory and catalog file; never recurse into profiles or active
  # nfqws configuration, which remain root/helper-owned.
  if [ -e "$ETC_DIR/zapret" ]; then
    [ -d "$ETC_DIR/zapret" ] && [ ! -L "$ETC_DIR/zapret" ] || {
      echo "install blocked: Zapret metadata root is not a directory" >&2
      return 1
    }
    chown "0:$controller_gid" "$ETC_DIR/zapret" || {
      echo "install blocked: cannot assign Zapret metadata root" >&2
      return 1
    }
    chmod 750 "$ETC_DIR/zapret" || {
      echo "install blocked: cannot make Zapret metadata root traversable" >&2
      return 1
    }
  fi
  if [ -e "$ETC_DIR/zapret/catalog.json" ]; then
    [ -f "$ETC_DIR/zapret/catalog.json" ] && [ ! -L "$ETC_DIR/zapret/catalog.json" ] || {
      echo "install blocked: Zapret catalog is not a regular file" >&2
      return 1
    }
    chown "0:$controller_gid" "$ETC_DIR/zapret/catalog.json" || {
      echo "install blocked: cannot assign Zapret catalog" >&2
      return 1
    }
    chmod 660 "$ETC_DIR/zapret/catalog.json" || {
      echo "install blocked: cannot make Zapret catalog writable" >&2
      return 1
    }
  fi
  validate_managed_secret_paths || return 1
  chown "$controller_uid:$controller_gid" "$ETC_DIR/secrets" || {
    echo "install blocked: cannot assign secrets directory" >&2
    return 1
  }
  chmod 750 "$ETC_DIR/config" "$ETC_DIR/secrets" "$STATE_DIR" "$RUNTIME_DIR"
  # The staged prefix is immutable code/assets, not controller state. Only the
  # two trees copied from this release are normalized here. The preserved
  # components runtime is a separate lifecycle-owned resource and must not be
  # recursively chmod'ed as a side effect of an installer upgrade.
  chmod a+rx "$PREFIX" || {
    echo "install blocked: cannot make managed prefix traversable" >&2
    return 1
  }
  for code_root in "$PREFIX/scripts" "$PREFIX/openwrt"; do
    [ -d "$code_root" ] || continue
    find "$code_root" -type d -exec chmod a+rx {} \; || {
      echo "install blocked: cannot make managed code directories readable: $code_root" >&2
      return 1
    }
    find "$code_root" -type f -exec chmod a+rX {} \; || {
      echo "install blocked: cannot make managed code files readable: $code_root" >&2
      return 1
    }
  done
  chmod 640 "$ETC_DIR/config/default.json" "$ETC_DIR/config/schema.json" "$ETC_DIR/config/listener.conf" "$ETC_DIR/helper.env"
  for secret_file in \
    "$ETC_DIR/secrets/vpn-subscription-url" \
    "$ETC_DIR/secrets/vpn-subscription-url.hwid.json" \
    "$ETC_DIR/secrets/happ-crypt4-private-key.pem" \
    "$ETC_DIR/secrets/telegram.json" \
    "$ETC_DIR/secrets/webhook.env"; do
    [ -e "$secret_file" ] || continue
    chown "$controller_uid:$controller_gid" "$secret_file" || {
      echo "install blocked: cannot assign managed secret: $secret_file" >&2
      return 1
    }
    chmod 600 "$secret_file"
  done
}

validate_managed_secret_paths() {
  [ ! -L "$ETC_DIR/secrets" ] || {
    echo "install blocked: secrets directory is a symlink" >&2
    return 1
  }
  for secret_file in \
    "$ETC_DIR/secrets/vpn-subscription-url" \
    "$ETC_DIR/secrets/vpn-subscription-url.hwid.json" \
    "$ETC_DIR/secrets/happ-crypt4-private-key.pem" \
    "$ETC_DIR/secrets/telegram.json" \
    "$ETC_DIR/secrets/webhook.env"; do
    [ ! -L "$secret_file" ] || {
      echo "install blocked: managed secret is a symlink: $secret_file" >&2
      return 1
    }
  done
}

activate_dns_observer() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  observer="$PREFIX/openwrt/ensure-dns-observer.sh"
  [ -x "$observer" ] || {
    echo "install blocked: DNS observation bootstrap helper is unavailable" >&2
    return 1
  }
  # Creating the confdir fragment is part of the reversible install.  Do not
  # restart dnsmasq while rollback is armed: a failed install must not leave a
  # runtime service side effect outside its manifest.
  "$observer"
}

reload_dns_observer_after_success() {
  [ -z "$SYSTEM_ROOT" ] || return 0
  observer="$PREFIX/openwrt/ensure-dns-observer.sh"
  [ -x "$observer" ] || return 1
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
    echo "== setup token =="
    ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$ROUTER_POLICY_BIN" auth setup-token --if-needed
    # The root-side backup/auth commands above may create or replace files in
    # the state tree. Normalize controller ownership only after the final
    # privileged write, immediately before any service can start.
    prepare_controller_identity
    restart_running_services
    if [ "$enable_services" = "1" ]; then
      run_bounded "$INIT_DIR/router-policy-dns-observer" enable
      run_bounded "$INIT_DIR/router-policy-boot-guard" enable
      run_bounded "$INIT_DIR/router-policy-helper" enable
      run_bounded "$INIT_DIR/router-policy" enable
      run_bounded "$INIT_DIR/router-policy-watchdog" enable
      start_control_services
      echo "services_enabled=router-policy-dns-observer router-policy-boot-guard router-policy-helper router-policy router-policy-watchdog"
      echo "control_services_running=router-policy-helper router-policy router-policy-watchdog"
      echo "dataplane_services_boot_enabled=false"
    else
      echo "services_enabled=false"
      echo "enable_services_with=install.sh --install --enable-services"
    fi
    post_install_ok=1
    if [ "$enable_services" = "1" ]; then
      if reload_dns_observer_after_success; then
        echo "dns_observer_reload=ok"
      else
        post_install_ok=0
        echo "dns_observer_reload=failed" >&2
        echo "dns_observer_action=retry_from_UI_or_restart_dnsmasq"
      fi
    fi
    if finalize_prefix_switch; then
      echo "prefix_switch_finalize=ok"
    else
      post_install_ok=0
      echo "install warning: previous prefix generation could not be cleaned" >&2
    fi
    # Retention pruning is deliberately last.  Until the new generation has
    # passed validation, service recovery and control-plane health checks, the
    # previous backup is part of the rollback contract and must not disappear.
    if [ "$post_install_ok" = "1" ]; then
      if "$ROUTER_POLICY_BIN" backup prune --root "$BACKUP_ROOT" --max 2 --max-bytes 134217728 --apply >/dev/null; then
        echo "backup_prune=ok"
      else
        echo "backup_prune=failed" >&2
        echo "backup_prune_action=retry_after_install" >&2
      fi
    else
      echo "backup_prune=skipped_post_install_verification_incomplete" >&2
    fi
    if [ "$post_install_ok" != "1" ]; then
      echo "install failed: post-install verification did not complete; automatic rollback is being attempted" >&2
      exit 1
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
