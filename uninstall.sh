#!/bin/sh
set -eu
umask 077

SYSTEM_ROOT="${ROUTER_POLICY_SYSTEM_ROOT:-}"
PREFIX="${PREFIX:-$SYSTEM_ROOT/usr/lib/router-policy}"
ETC_DIR="${ETC_DIR:-$SYSTEM_ROOT/etc/router-policy}"
STATE_DIR="${STATE_DIR:-$ETC_DIR/state}"
BIN_DIR="${BIN_DIR:-$SYSTEM_ROOT/usr/bin}"
RUNTIME_DIR="${RUNTIME_DIR:-$SYSTEM_ROOT/tmp/router-policy}"
INIT_DIR="${INIT_DIR:-$SYSTEM_ROOT/etc/init.d}"
HOTPLUG_IFACE_DIR="${HOTPLUG_IFACE_DIR:-$SYSTEM_ROOT/etc/hotplug.d/iface}"
HOTPLUG_FIREWALL_DIR="${HOTPLUG_FIREWALL_DIR:-$SYSTEM_ROOT/etc/hotplug.d/firewall}"
DNSMASQ_DIR="${DNSMASQ_DIR:-$SYSTEM_ROOT/tmp/dnsmasq.d}"
NFTABLES_DIR="${NFTABLES_DIR:-$SYSTEM_ROOT/etc/nftables.d}"
BACKUP_ROOT="${BACKUP_ROOT:-$SYSTEM_ROOT/root/router-policy-backups}"
BACKUP_DIR="${BACKUP_DIR:-$BACKUP_ROOT/uninstall-$(date -u +%Y%m%dT%H%M%SZ)}"
ROUTER_POLICY_VERSION="${ROUTER_POLICY_VERSION:-unknown}"
TAR_BIN="${TAR_BIN:-tar}"
UCI_BIN="${UCI_BIN:-uci}"
PIDOF_BIN="${PIDOF_BIN:-pidof}"
NSLOOKUP_BIN="${NSLOOKUP_BIN:-nslookup}"
SLEEP_BIN="${SLEEP_BIN:-sleep}"
NFT_BIN="${NFT_BIN:-nft}"
SERVICES="router-policy-dns-observer router-policy-boot-guard router-policy-helper router-policy-watchdog router-policy router-policy-xray router-policy-zapret"
mode="${1:---dry-run}"

delete_owned_nft_table() {
  table="$1"
  tables="$($NFT_BIN list tables 2>/dev/null)" || {
    echo "uninstall blocked: nft table inventory failed" >&2
    return 1
  }
  if ! printf '%s\n' "$tables" | grep -Eq "^table[[:space:]]+inet[[:space:]]+${table}[[:space:]]*$"; then
    return 0
  fi
  current="$($NFT_BIN list table inet "$table" 2>/dev/null)" || {
    echo "uninstall blocked: owned nft table could not be inspected: $table" >&2
    return 1
  }
  printf '%s\n' "$current" | grep -F 'comment "router-policy owner=flintroute"' >/dev/null || {
    echo "uninstall blocked: nft table ownership is not proven: $table" >&2
    return 1
  }
  "$NFT_BIN" delete table inet "$table" || {
    echo "uninstall failed: owned nft table could not be removed: $table" >&2
    return 1
  }
  if "$NFT_BIN" list table inet "$table" >/dev/null 2>&1; then
    echo "uninstall failed: owned nft table still exists: $table" >&2
    return 1
  fi
}

validate_no_symlink_path() {
  candidate="$1"
  case "$candidate" in
    /*) ;;
    *) return 1 ;;
  esac
  remainder=${candidate#/}
  current=""
  while [ -n "$remainder" ]; do
    case "$remainder" in
      */*) component=${remainder%%/*}; remainder=${remainder#*/} ;;
      *) component=$remainder; remainder= ;;
    esac
    [ -n "$component" ] || continue
    current="$current/$component"
    [ ! -L "$current" ] || return 1
  done
}

deactivate_committed_dataplane() {
  binding="$STATE_DIR/last-good/active-transaction.env"
  [ -f "$binding" ] || binding="$STATE_DIR/last-good/transaction.env"
  [ -f "$binding" ] || {
    restore_flow_offloading_baseline
    echo "dataplane_deactivation=skipped-no-last-good"
    return 0
  }
  transaction_id="$(sed -n 's/^transaction_id=//p' "$binding" | head -n 1)"
  revision_id="$(sed -n 's/^revision_id=//p' "$binding" | head -n 1)"
  candidate_hash="$(sed -n 's/^candidate_hash=//p' "$binding" | head -n 1)"
  printf '%s\n' "$transaction_id" | grep -Eq '^tx_[0-9a-f]{16}$' || {
    echo "uninstall blocked: invalid committed transaction binding" >&2
    return 1
  }
  printf '%s\n' "$revision_id" | grep -Eq '^rev_[0-9]+_[0-9a-f]{12}$' || {
    echo "uninstall blocked: invalid committed revision binding" >&2
    return 1
  }
  printf '%s\n' "$candidate_hash" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    echo "uninstall blocked: invalid committed candidate hash" >&2
    return 1
  }
  plan="$STATE_DIR/transactions/$revision_id/$transaction_id/generated/ip-plan.json"
  [ -f "$plan" ] && [ ! -L "$plan" ] || {
    echo "uninstall blocked: committed IP plan is unavailable" >&2
    return 1
  }
  mkdir -p "$RUNTIME_DIR"
  empty_state="$RUNTIME_DIR/uninstall-empty-ip-state.json"
  printf '{"routes":[],"rules":[]}\n' >"$empty_state"
  chmod 600 "$empty_state"
  if ! ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$BIN_DIR/router-policy" internal-rollback-ip-state \
    --plan "$plan" \
    --transaction "$transaction_id" \
    --revision "$revision_id" \
    --candidate-hash "$candidate_hash" \
    --pre-state "$empty_state"; then
    rm -f "$empty_state"
    echo "uninstall blocked: committed IP resources could not be removed safely" >&2
    return 1
  fi
  rm -f "$empty_state"
  restore_flow_offloading_baseline
  echo "dataplane_deactivation=verified"
}

file_mode_bits() {
  target="$1"
  # Paths are fixed and allowlisted. BusyBox ls is present on factory OpenWrt.
  # shellcheck disable=SC2012
  permissions="$(LC_ALL=C ls -ld "$target" 2>/dev/null | awk '{print substr($1, 1, 10)}')"
  case "$permissions" in
    -rw-------) echo 600 ;;
    drwx------) echo 700 ;;
    *) return 1 ;;
  esac
}

file_owner_id() {
  target="$1"
  # shellcheck disable=SC2012
  LC_ALL=C ls -ldn "$target" 2>/dev/null | awk '{print $3}'
}

restore_flow_offloading_baseline() {
  baseline="$STATE_DIR/ownership/flow-offloading.env"
  ownership_dir="$(dirname "$baseline")"
  [ -e "$baseline" ] || {
    echo "flow_offloading_restore=skipped-no-owned-baseline"
    return 0
  }
  [ -d "$ownership_dir" ] && [ ! -L "$ownership_dir" ] || {
    echo "uninstall blocked: flow-offloading ownership directory is invalid" >&2
    return 1
  }
  [ -f "$baseline" ] && [ ! -L "$baseline" ] || {
    echo "uninstall blocked: flow-offloading baseline is not a regular file" >&2
    return 1
  }
  baseline_mode="$(file_mode_bits "$baseline")"
  baseline_owner="$(file_owner_id "$baseline")"
  ownership_owner="$(file_owner_id "$ownership_dir")"
  [ "$baseline_mode" = 600 ] && [ -n "$baseline_owner" ] && [ "$baseline_owner" = "$ownership_owner" ] || {
    echo "uninstall blocked: flow-offloading baseline permissions are invalid" >&2
    return 1
  }
  schema="$(sed -n 's/^schema_version=//p' "$baseline" | head -n 1)"
  software="$(sed -n 's/^software=//p' "$baseline" | head -n 1)"
  hardware="$(sed -n 's/^hardware=//p' "$baseline" | head -n 1)"
  [ "$schema" = 1 ] || { echo "uninstall blocked: flow-offloading baseline schema is invalid" >&2; return 1; }
  case "$software:$hardware" in
    0:0|0:1|0:absent|1:0|1:1|1:absent|absent:0|absent:1|absent:absent) ;;
    *) echo "uninstall blocked: flow-offloading baseline value is invalid" >&2; return 1 ;;
  esac
  case "$software" in
    absent)
      if "$UCI_BIN" -q get 'firewall.@defaults[0].flow_offloading' >/dev/null 2>&1; then
        "$UCI_BIN" delete 'firewall.@defaults[0].flow_offloading' || {
          echo "uninstall blocked: failed to remove software flow-offloading option" >&2
          return 1
        }
      fi
      ;;
    0|1) "$UCI_BIN" set "firewall.@defaults[0].flow_offloading=$software" ;;
  esac
  case "$hardware" in
    absent)
      if "$UCI_BIN" -q get 'firewall.@defaults[0].flow_offloading_hw' >/dev/null 2>&1; then
        "$UCI_BIN" delete 'firewall.@defaults[0].flow_offloading_hw' || {
          echo "uninstall blocked: failed to remove hardware flow-offloading option" >&2
          return 1
        }
      fi
      ;;
    0|1) "$UCI_BIN" set "firewall.@defaults[0].flow_offloading_hw=$hardware" ;;
  esac
  "$UCI_BIN" commit firewall
  echo "flow_offloading_restore=persistent-baseline-restored"
  echo "flow_offloading_runtime_reload=deferred"
}

wait_dnsmasq_ready() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if "$PIDOF_BIN" dnsmasq >/dev/null 2>&1 &&
      "$NSLOOKUP_BIN" localhost 127.0.0.1 >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    "$SLEEP_BIN" 1
  done
  return 1
}

if [ "${ROUTER_POLICY_UNINSTALL_LIB_ONLY:-0}" = "1" ]; then
  return 0
fi

if [ "$mode" = "--dry-run" ]; then
  echo "would_stop_services=router-policy-dns-observer router-policy-boot-guard router-policy-helper router-policy-watchdog router-policy router-policy-xray router-policy-zapret"
  echo "would_remove_prefix=$PREFIX"
  echo "would_keep_backup=$BACKUP_DIR"
  exit 0
fi

[ "$mode" = "--uninstall" ] || { echo "usage: uninstall.sh --dry-run|--uninstall" >&2; exit 2; }
[ -n "$SYSTEM_ROOT" ] || [ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 1; }
[ "$PREFIX" = "$SYSTEM_ROOT/usr/lib/router-policy" ] || {
  echo "uninstall blocked: non-standard project prefix" >&2
  exit 1
}
[ "$RUNTIME_DIR" = "$SYSTEM_ROOT/tmp/router-policy" ] || {
  echo "uninstall blocked: non-standard runtime root" >&2
  exit 1
}

if [ -z "$SYSTEM_ROOT" ] && [ -x "$BIN_DIR/router-policy" ]; then
  ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$BIN_DIR/router-policy" maintenance begin --owner "installer:uninstall-$$" --reason uninstall --lease 30m >/dev/null
fi

for owned_path in "$PREFIX" "$BIN_DIR/router-policy" "$INIT_DIR/router-policy" \
  "$INIT_DIR/router-policy-dns-observer" "$INIT_DIR/router-policy-boot-guard" \
  "$INIT_DIR/router-policy-watchdog" "$INIT_DIR/router-policy-xray" \
  "$INIT_DIR/router-policy-zapret" "$HOTPLUG_IFACE_DIR/95-router-policy" \
  "$HOTPLUG_FIREWALL_DIR/95-router-policy" "$ETC_DIR" "$RUNTIME_DIR"; do
  validate_no_symlink_path "$owned_path" || {
    echo "uninstall blocked: symlink in owned path: $owned_path" >&2
    exit 1
  }
done

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

if [ -z "$SYSTEM_ROOT" ]; then
  deactivate_committed_dataplane >"$BACKUP_DIR/dataplane-deactivation.txt"
  if command -v "$NFT_BIN" >/dev/null 2>&1; then
    delete_owned_nft_table router_policy
    delete_owned_nft_table router_policy_boot_guard
  fi
fi

if [ -x "$BIN_DIR/router-policy" ]; then
  "$BIN_DIR/router-policy" backup register --root "$BACKUP_DIR" --operation "$(basename "$BACKUP_DIR")" --version "$ROUTER_POLICY_VERSION" --reason uninstall --retention-class uninstall-fallback >/dev/null
  "$BIN_DIR/router-policy" backup prune --root "$BACKUP_ROOT" --max 2 --max-bytes 134217728 --apply >/dev/null
fi

if [ -z "$SYSTEM_ROOT" ]; then
  for service in $SERVICES; do
    init="$INIT_DIR/$service"
    if [ -x "$init" ]; then
      "$init" stop || {
        echo "uninstall failed: could not stop $service" >&2
        exit 1
      }
      "$init" disable || {
        echo "uninstall failed: could not disable $service" >&2
        exit 1
      }
    fi
  done
fi

rm -f "$INIT_DIR/router-policy-helper" "$INIT_DIR/router-policy" "$INIT_DIR/router-policy-dns-observer" "$INIT_DIR/router-policy-boot-guard" "$INIT_DIR/router-policy-watchdog" "$INIT_DIR/router-policy-xray" "$INIT_DIR/router-policy-zapret"
rm -f "$BIN_DIR/router-policy-helper"
rm -f "$HOTPLUG_IFACE_DIR/95-router-policy" "$HOTPLUG_FIREWALL_DIR/95-router-policy"
rm -f "$ETC_DIR/firewall/router-policy.nft" "$NFTABLES_DIR/router-policy.nft" "$DNSMASQ_DIR/router-policy.conf"
rm -f "$BIN_DIR/router-policy"
rm -rf "$PREFIX"
rm -rf "$RUNTIME_DIR"

if [ -z "$SYSTEM_ROOT" ] && [ -x "$INIT_DIR/dnsmasq" ]; then
  "$INIT_DIR/dnsmasq" restart
  wait_dnsmasq_ready || {
    echo "uninstall failed: dnsmasq did not become ready" >&2
    exit 1
  }
fi

echo "uninstalled=true"
echo "backup=$BACKUP_DIR"
