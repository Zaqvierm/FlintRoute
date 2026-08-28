#!/bin/sh
set -eu
umask 077

SYSTEM_ROOT="${ROUTER_POLICY_SYSTEM_ROOT:-}"
PREFIX="${PREFIX:-$SYSTEM_ROOT/usr/lib/router-policy}"
MANAGED_FILE_MANIFEST="$PREFIX/.managed-files.manifest"
ETC_DIR="${ETC_DIR:-$SYSTEM_ROOT/etc/router-policy}"
STATE_DIR="${STATE_DIR:-$ETC_DIR/state}"
BIN_DIR="${BIN_DIR:-$SYSTEM_ROOT/usr/bin}"
RUNTIME_DIR="${RUNTIME_DIR:-$SYSTEM_ROOT/tmp/router-policy}"
INIT_DIR="${INIT_DIR:-$SYSTEM_ROOT/etc/init.d}"
HOTPLUG_IFACE_DIR="${HOTPLUG_IFACE_DIR:-$SYSTEM_ROOT/etc/hotplug.d/iface}"
HOTPLUG_FIREWALL_DIR="${HOTPLUG_FIREWALL_DIR:-$SYSTEM_ROOT/etc/hotplug.d/firewall}"
DNSMASQ_DIR="${DNSMASQ_DIR:-$SYSTEM_ROOT/tmp/dnsmasq.d}"
NFTABLES_DIR="${NFTABLES_DIR:-$SYSTEM_ROOT/etc/nftables.d}"
ZAPRET_PROFILE_DIR="${ZAPRET_PROFILE_DIR:-$ETC_DIR/zapret/profiles}"
ZAPRET_PROFILE_MANIFEST="${ZAPRET_PROFILE_MANIFEST:-$ETC_DIR/zapret/profiles.manifest}"
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
  # Uninstall paths come from environment-derived roots.  Reject lexical
  # traversal and ambiguous separators before tar/rm can resolve them to a
  # parent outside the fixed FlintRoute ownership boundary.
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
    "":*|*:|/:*|*:/)
      echo "uninstall blocked: invalid backup root" >&2
      return 1
      ;;
  esac
  case "$BACKUP_DIR" in
    "$BACKUP_ROOT"/*) ;;
    *)
      echo "uninstall blocked: backup directory is outside backup root" >&2
      return 1
      ;;
  esac
  validate_no_symlink_path "$BACKUP_ROOT" || {
    echo "uninstall blocked: symlink or non-canonical backup root path" >&2
    return 1
  }
  validate_no_symlink_path "$BACKUP_DIR" || {
    echo "uninstall blocked: symlink or non-canonical backup directory path" >&2
    return 1
  }
  for critical_path in "$SYSTEM_ROOT" "$SYSTEM_ROOT/etc" "$SYSTEM_ROOT/usr" "$SYSTEM_ROOT/usr/bin" "$SYSTEM_ROOT/usr/lib" "$SYSTEM_ROOT/etc/init.d" "$SYSTEM_ROOT/etc/hotplug.d"; do
    [ -n "$critical_path" ] || continue
    case "$BACKUP_ROOT/" in
      "$critical_path"/*)
        echo "uninstall blocked: backup root is inside a system directory: $BACKUP_ROOT" >&2
        return 1
        ;;
    esac
  done
}

runtime_top_entry_allowed() {
  case "$1" in
    active-transaction.env|pending-transaction.env|boot-guard.nft|dns-observations.log|install-health.json|write-events.log|uninstall-empty-ip-state.json)
      return 0 ;;
    nft-transition-tx_*.nft|nft-boot-guard-transition-tx_*.nft|management-proof-*.error)
      printf '%s\n' "$1" | grep -Eq '^(nft-transition|nft-boot-guard-transition)-tx_[0-9a-f]{16}\.nft$|^management-proof-rev_[0-9]+_[0-9a-f]{12}-tx_[0-9a-f]{16}\.error$'
      ;;
    transaction.lock|rollback-timers|management-proofs)
      return 0 ;;
    *)
      return 1 ;;
  esac
}

validate_runtime_contents() {
  [ -e "$RUNTIME_DIR" ] || return 0
  [ -d "$RUNTIME_DIR" ] && [ ! -L "$RUNTIME_DIR" ] || {
    echo "uninstall blocked: runtime root is not an owned directory" >&2
    return 1
  }
  for entry in "$RUNTIME_DIR"/* "$RUNTIME_DIR"/.[!.]* "$RUNTIME_DIR"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    name="${entry##*/}"
    runtime_top_entry_allowed "$name" || {
      echo "uninstall blocked: unowned runtime entry: $entry" >&2
      return 1
    }
    case "$name" in
      transaction.lock|rollback-timers|management-proofs)
        [ -d "$entry" ] && [ ! -L "$entry" ] || {
          echo "uninstall blocked: owned runtime directory is invalid: $entry" >&2
          return 1
        }
        for nested in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
          [ -e "$nested" ] || [ -L "$nested" ] || continue
          [ -f "$nested" ] && [ ! -L "$nested" ] || {
            echo "uninstall blocked: unowned runtime child: $nested" >&2
            return 1
          }
          nested_name="${nested##*/}"
          case "$name:$nested_name" in
            transaction.lock:metadata.env)
              ;;
            rollback-timers:*)
              printf '%s\n' "$nested_name" | grep -Eq '^rev_[0-9]+_[0-9a-f]{12}-tx_[0-9a-f]{16}\.env(\.bootstrap(\.tmp)?)?$' || {
                echo "uninstall blocked: unowned rollback timer: $nested" >&2
                return 1
              }
              ;;
            management-proofs:*)
              printf '%s\n' "$nested_name" | grep -Eq '^rev_[0-9]+_[0-9a-f]{12}-tx_[0-9a-f]{16}\.json$' || {
                echo "uninstall blocked: unowned management proof: $nested" >&2
                return 1
              }
              ;;
            *)
              echo "uninstall blocked: unowned runtime child: $nested" >&2
              return 1
              ;;
          esac
        done
        ;;
      *)
        [ -f "$entry" ] && [ ! -L "$entry" ] || {
          echo "uninstall blocked: owned runtime file is invalid: $entry" >&2
          return 1
        }
        ;;
    esac
  done
}

remove_owned_runtime() {
  validate_runtime_contents || return 1
  [ -e "$RUNTIME_DIR" ] || return 0
  for entry in "$RUNTIME_DIR"/* "$RUNTIME_DIR"/.[!.]* "$RUNTIME_DIR"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    name="${entry##*/}"
    case "$name" in
      transaction.lock|rollback-timers|management-proofs)
        for nested in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
          [ -e "$nested" ] || [ -L "$nested" ] || continue
          rm -f "$nested"
        done
        rmdir "$entry" || return 1
        ;;
      *)
        rm -f "$entry"
        ;;
    esac
  done
  rmdir "$RUNTIME_DIR" || {
    echo "uninstall failed: owned runtime directory is not empty" >&2
    return 1
  }
}

deactivate_committed_dataplane() {
  binding="$STATE_DIR/last-good/active-transaction.env"
  [ -f "$binding" ] || binding="$STATE_DIR/last-good/transaction.env"
  [ -f "$binding" ] || {
    # Absence of last-good is not proof that no dataplane was ever committed.
    # A crash can leave transaction journals while the binding write is still
    # missing.  Never claim a safe empty state in that case: without the
    # journal's exact IP plan there is no ownership proof for cleanup.
    if [ -d "$STATE_DIR/transactions" ] && [ -n "$(ls -A "$STATE_DIR/transactions" 2>/dev/null)" ]; then
      echo "uninstall blocked: committed transaction binding is missing while transaction journals remain" >&2
      return 1
    fi
    restore_flow_offloading_baseline
    echo "dataplane_deactivation=verified-empty"
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

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    echo "uninstall blocked: neither sha256sum nor openssl is available" >&2
    return 1
  fi
}

managed_static_paths() {
  printf '%s\n' \
    "$BIN_DIR/router-policy" \
    "$BIN_DIR/router-policy-helper" \
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

validate_managed_file_manifest() {
  [ -f "$MANAGED_FILE_MANIFEST" ] && [ ! -L "$MANAGED_FILE_MANIFEST" ] || {
    echo "uninstall blocked: managed-file ownership manifest is missing" >&2
    return 1
  }
  [ "$(file_mode_bits "$MANAGED_FILE_MANIFEST")" = 600 ] || {
    echo "uninstall blocked: managed-file ownership manifest mode is invalid" >&2
    return 1
  }
  if [ -z "$SYSTEM_ROOT" ]; then
    [ "$(file_owner_id "$MANAGED_FILE_MANIFEST")" = 0 ] || {
      echo "uninstall blocked: managed-file ownership manifest is not root-owned" >&2
      return 1
    }
  fi
  while IFS='|' read -r managed_path expected_hash extra; do
    [ -n "${managed_path:-}" ] || continue
    [ -z "${extra:-}" ] || {
      echo "uninstall blocked: malformed managed-file ownership manifest" >&2
      return 1
    }
    printf '%s\n' "$expected_hash" | grep -Eq '^[0-9a-f]{64}$' || {
      echo "uninstall blocked: malformed managed-file hash" >&2
      return 1
    }
    is_known=0
    while IFS= read -r known_path; do
      [ "$managed_path" = "$known_path" ] && is_known=1
    done <<EOF
$(managed_static_paths)
EOF
    [ "$is_known" = 1 ] || {
      echo "uninstall blocked: unknown managed-file manifest path: $managed_path" >&2
      return 1
    }
    if [ -e "$managed_path" ] || [ -L "$managed_path" ]; then
      [ -f "$managed_path" ] && [ ! -L "$managed_path" ] || {
        echo "uninstall blocked: managed static file is not regular: $managed_path" >&2
        return 1
      }
      actual_hash="$(hash_file "$managed_path")" || return 1
      [ "$actual_hash" = "$expected_hash" ] || {
        echo "uninstall blocked: managed static file ownership/content is unproven: $managed_path" >&2
        return 1
      }
    fi
  done < "$MANAGED_FILE_MANIFEST"
  while IFS= read -r known_path; do
    [ -e "$known_path" ] || [ -L "$known_path" ] || continue
    grep -F -e "$known_path|" "$MANAGED_FILE_MANIFEST" >/dev/null 2>&1 || {
      # The manifest is the authority for deleting a present static path.  A
      # missing entry is treated as foreign rather than guessed away.
      echo "uninstall blocked: present managed path is not in ownership manifest: $known_path" >&2
      return 1
    }
  done <<EOF
$(managed_static_paths)
EOF
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

profile_id_valid() {
  printf '%s\n' "$1" | grep -Eq '^[a-z0-9][a-z0-9-]{0,31}$'
}

profile_manifest_validate() {
  manifest="$1"
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
  # Stop and disable every owned profile first. Do not remove the first
  # profile's files while a later profile can still fail to stop; otherwise a
  # partial teardown would destroy metadata needed to recover it.
  while IFS='|' read -r profile_id profile_config profile_init profile_queue extra; do
    [ -z "${profile_id:-}" ] && continue
    [ -z "${extra:-}" ] || return 1
    profile_id_valid "$profile_id" || return 1
    [ "$profile_config" = "$ZAPRET_PROFILE_DIR/$profile_id.conf" ] || return 1
    [ "$profile_init" = "$INIT_DIR/router-policy-zapret-$profile_id" ] || return 1
    case "$profile_queue" in ''|*[!0-9]*) return 1;; esac
    [ "$profile_queue" -ge 2 ] || return 1
  done < "$manifest"
}

remove_owned_profile_resources() {
  [ "$ZAPRET_PROFILE_DIR" = "$ETC_DIR/zapret/profiles" ] || {
    echo "uninstall blocked: non-standard Zapret profile directory" >&2
    return 1
  }
  [ "$ZAPRET_PROFILE_MANIFEST" = "$ETC_DIR/zapret/profiles.manifest" ] || {
    echo "uninstall blocked: non-standard Zapret profile manifest" >&2
    return 1
  }
  [ -e "$ZAPRET_PROFILE_MANIFEST" ] || return 0
  validate_no_symlink_path "$ZAPRET_PROFILE_MANIFEST" || {
    echo "uninstall blocked: unsafe Zapret profile manifest path" >&2
    return 1
  }
  profile_manifest_validate "$ZAPRET_PROFILE_MANIFEST" || {
    echo "uninstall blocked: invalid Zapret profile ownership manifest" >&2
    return 1
  }
  while IFS='|' read -r profile_id profile_config profile_init profile_queue extra; do
    [ -z "${profile_id:-}" ] && continue
    validate_no_symlink_path "$profile_config" || return 1
    validate_no_symlink_path "$profile_init" || return 1
    if [ -z "$SYSTEM_ROOT" ] && [ -x "$profile_init" ]; then
      "$profile_init" stop || {
        echo "uninstall failed: could not stop router-policy-zapret-$profile_id" >&2
        return 1
      }
      "$profile_init" disable || {
        echo "uninstall failed: could not disable router-policy-zapret-$profile_id" >&2
        return 1
      }
    fi
  done < "$ZAPRET_PROFILE_MANIFEST"
  while IFS='|' read -r profile_id profile_config profile_init profile_queue extra; do
    [ -z "${profile_id:-}" ] && continue
    rm -f "$profile_config" "$profile_init"
  done < "$ZAPRET_PROFILE_MANIFEST"
  rm -f "$ZAPRET_PROFILE_MANIFEST"
}

if [ "${ROUTER_POLICY_UNINSTALL_LIB_ONLY:-0}" = "1" ]; then
  return 0
fi

if [ "$mode" = "--dry-run" ]; then
  echo "would_stop_services=router-policy-dns-observer router-policy-boot-guard router-policy-helper router-policy-watchdog router-policy router-policy-xray router-policy-zapret"
  echo "would_remove_prefix=$PREFIX"
  echo "would_keep_backup=$BACKUP_DIR"
  echo "would_remove_owned_zapret_profiles=$ZAPRET_PROFILE_MANIFEST"
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
validate_backup_paths || exit 1

if [ -z "$SYSTEM_ROOT" ] && [ -x "$BIN_DIR/router-policy" ]; then
  ROUTER_POLICY_CONFIG="$ETC_DIR/config/default.json" "$BIN_DIR/router-policy" maintenance begin --owner "installer:uninstall-$$" --reason uninstall --lease 30m >/dev/null
fi

for owned_path in "$PREFIX" "$BIN_DIR/router-policy" "$INIT_DIR/router-policy" \
  "$INIT_DIR/router-policy-dns-observer" "$INIT_DIR/router-policy-boot-guard" \
  "$INIT_DIR/router-policy-watchdog" "$INIT_DIR/router-policy-xray" \
  "$INIT_DIR/router-policy-zapret" "$HOTPLUG_IFACE_DIR/95-router-policy" \
  "$HOTPLUG_FIREWALL_DIR/95-router-policy" "$ETC_DIR" "$RUNTIME_DIR" \
  "$ZAPRET_PROFILE_MANIFEST" "$ZAPRET_PROFILE_DIR"; do
  validate_no_symlink_path "$owned_path" || {
    echo "uninstall blocked: symlink in owned path: $owned_path" >&2
    exit 1
  }
done
validate_runtime_contents || exit 1
validate_managed_file_manifest || exit 1

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

remove_owned_profile_resources

if [ -x "$BIN_DIR/router-policy" ]; then
  "$BIN_DIR/router-policy" backup register --root "$BACKUP_DIR" --operation "$(basename "$BACKUP_DIR")" --version "$ROUTER_POLICY_VERSION" --reason uninstall --retention-class uninstall-fallback >/dev/null
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

while IFS= read -r managed_path; do
  [ -n "$managed_path" ] || continue
  # Keep the controller binary alive until final backup pruning; it is the
  # executable that performs the pruning operation itself.
  [ "$managed_path" = "$BIN_DIR/router-policy" ] && continue
  rm -f "$managed_path"
done <<EOF
$(managed_static_paths)
EOF
rm -f "$ETC_DIR/firewall/router-policy.nft" "$NFTABLES_DIR/router-policy.nft" "$DNSMASQ_DIR/router-policy.conf"
rm -rf "$PREFIX"

if [ -z "$SYSTEM_ROOT" ] && [ -x "$INIT_DIR/dnsmasq" ]; then
  "$INIT_DIR/dnsmasq" restart
  wait_dnsmasq_ready || {
    echo "uninstall failed: dnsmasq did not become ready" >&2
    exit 1
  }
fi

remove_owned_runtime || exit 1

# Keep older fallback backups until every teardown and the final dnsmasq
# readiness check has succeeded.  A failed uninstall must not prune the only
# recovery points that still describe the previous installation.
if [ -x "$BIN_DIR/router-policy" ]; then
  "$BIN_DIR/router-policy" backup prune --root "$BACKUP_ROOT" --max 2 --max-bytes 134217728 --apply >/dev/null
fi
rm -f "$BIN_DIR/router-policy"

echo "uninstalled=true"
echo "backup=$BACKUP_DIR"
