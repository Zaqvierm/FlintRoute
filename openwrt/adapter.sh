#!/bin/sh
set -eu
umask 077

cmd="${1:-}"
config="${2:-${ROUTER_POLICY_CONFIG_PATH:-/etc/router-policy/config/default.json}}"
txid="${3:-}"
revision="${4:-}"
recovery_candidate_hash="${5:-}"
recovery_artifact_manifest_hash="${6:-}"

runtime="${RUNTIME_DIR:-/tmp/router-policy}"
state="${STATE_DIR:-/etc/router-policy/state}"
txroot="$state/transactions"
ownership_dir="$state/ownership"
flow_offload_baseline="$ownership_dir/flow-offloading.env"
lock_dir="$runtime/transaction.lock"
pending_file="$runtime/pending-transaction.env"
active_file="$runtime/active-transaction.env"
boot_guard_file="$runtime/boot-guard.nft"
timer_dir="$runtime/rollback-timers"
known_config="${ROUTER_POLICY_CONFIG_PATH:-/etc/router-policy/config/default.json}"
router_policy_bin="${ROUTER_POLICY_BIN:-/usr/bin/router-policy}"
adapter_self="${ROUTER_POLICY_ADAPTER_SELF:-/usr/lib/router-policy/openwrt/adapter.sh}"
nft_bin="${NFT_BIN:-nft}"
dnsmasq_bin="${DNSMASQ_BIN:-dnsmasq}"
dnsmasq_init="${DNSMASQ_INIT:-/etc/init.d/dnsmasq}"
xray_bin="${XRAY_BIN:-xray}"
xray_init="${XRAY_INIT:-/etc/init.d/router-policy-xray}"
nfqws_bin="${NFQWS_BIN:-/usr/bin/nfqws}"
zapret_init="${ZAPRET_INIT:-/etc/init.d/router-policy-zapret}"
ip_bin="${IP_BIN:-ip}"
uci_bin="${UCI_BIN:-uci}"
wget_bin="${WGET_BIN:-wget}"
nslookup_bin="${NSLOOKUP_BIN:-nslookup}"
pidof_bin="${PIDOF_BIN:-pidof}"

active_nft="${ACTIVE_NFT:-/etc/router-policy/firewall/router-policy.nft}"
active_dnsmasq="${ACTIVE_DNSMASQ:-/tmp/dnsmasq.d/router-policy.conf}"
active_xray="${ACTIVE_XRAY:-/etc/router-policy/xray/active.json}"
active_zapret="${ACTIVE_ZAPRET:-/etc/router-policy/zapret/nfqws.conf}"
active_zapret_profiles="${ACTIVE_ZAPRET_PROFILES:-${active_zapret%/*}/profiles.manifest}"
zapret_profile_dir="${ZAPRET_PROFILE_DIR:-/etc/router-policy/zapret/profiles}"
zapret_profile_init_prefix="${ZAPRET_PROFILE_INIT_PREFIX:-/etc/init.d/router-policy-zapret-}"
if [ "$runtime" = "/tmp/router-policy" ]; then
  dns_observation_log="${DNS_OBSERVATION_LOG:-/var/run/dnsmasq/router-policy-observations.log}"
else
  dns_observation_log="${DNS_OBSERVATION_LOG:-$runtime/dns-observations.log}"
fi
flow_offload_uci_key='firewall.@defaults[0].flow_offloading'
flow_offload_hw_uci_key='firewall.@defaults[0].flow_offloading_hw'

mkdir -p "$runtime" "$state/last-good" "$state/backups" "$txroot" "$timer_dir"

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

record_runtime_write_event() {
  event_kind="$1"
  event_bytes="${2:-0}"
  event_reason="$3"
  event_file="$runtime/write-events.log"
  printf '%s\t%s\t%s\t%s\n' "$(now_utc)" "$event_kind" "$event_bytes" "$event_reason" >> "$event_file"
  event_lines="$(wc -l < "$event_file" | tr -d ' ')"
  if [ "$event_lines" -gt 1024 ]; then
    tail -n 1024 "$event_file" > "$event_file.tmp"
    mv "$event_file.tmp" "$event_file"
  fi
}

process_start() {
  pid_value="$1"
  [ -r "/proc/$pid_value/stat" ] || return 1
  awk '{print $22}' "/proc/$pid_value/stat"
}

process_state() {
  pid_value="$1"
  [ -r "/proc/$pid_value/stat" ] || return 1
  awk '{print $3}' "/proc/$pid_value/stat"
}

process_terminated() {
  pid_value="$1"
  ! kill -0 "$pid_value" 2>/dev/null || [ "$(process_state "$pid_value" 2>/dev/null || true)" = "Z" ]
}

terminate_owned_timer_pid() {
  timer_pid_arg="$1"
  timer_start_arg="$2"
  process_terminated "$timer_pid_arg" && return 0
  current_timer_start="$(process_start "$timer_pid_arg" 2>/dev/null || true)"
  [ -n "$current_timer_start" ] && [ "$current_timer_start" = "$timer_start_arg" ] || return 1
  kill -TERM "$timer_pid_arg" 2>/dev/null || return 1
  timer_wait=0
  while [ "$timer_wait" -lt 5 ] && ! process_terminated "$timer_pid_arg"; do
    current_timer_start="$(process_start "$timer_pid_arg" 2>/dev/null || true)"
    [ "$current_timer_start" = "$timer_start_arg" ] || return 0
    sleep 1
    timer_wait=$((timer_wait + 1))
  done
  if ! process_terminated "$timer_pid_arg"; then
    current_timer_start="$(process_start "$timer_pid_arg" 2>/dev/null || true)"
    [ "$current_timer_start" = "$timer_start_arg" ] || return 1
    kill -KILL "$timer_pid_arg" 2>/dev/null || return 1
    sleep 1
    process_terminated "$timer_pid_arg" || return 1
  fi
}

lock_owner_alive() {
  [ -f "$lock_dir/metadata.env" ] || return 1
  lock_pid="$(sed -n 's/^pid=//p' "$lock_dir/metadata.env" | head -n 1)"
  lock_start="$(sed -n 's/^process_start=//p' "$lock_dir/metadata.env" | head -n 1)"
  [ -n "$lock_pid" ] && [ -n "$lock_start" ] || return 1
  kill -0 "$lock_pid" 2>/dev/null || return 1
  current_start="$(process_start "$lock_pid" 2>/dev/null || true)"
  [ -n "$current_start" ] && [ "$current_start" = "$lock_start" ]
}

release_lock() {
  [ -d "$lock_dir" ] || return 0
  owner_pid="$(sed -n 's/^pid=//p' "$lock_dir/metadata.env" 2>/dev/null | head -n 1)"
  owner_start="$(sed -n 's/^process_start=//p' "$lock_dir/metadata.env" 2>/dev/null | head -n 1)"
  self_start="$(process_start "$$" 2>/dev/null || true)"
  if [ "$owner_pid" = "$$" ] && [ -n "$self_start" ] && [ "$owner_start" = "$self_start" ]; then
    rm -f "$lock_dir/metadata.env"
    rmdir "$lock_dir" 2>/dev/null || true
  fi
}

take_lock() {
  if ! mkdir "$lock_dir" 2>/dev/null; then
    [ -f "$lock_dir/metadata.env" ] || {
      echo "reason=lock_metadata_missing_cannot_prove_stale" >&2
      exit 75
    }
    lock_pid="$(sed -n 's/^pid=//p' "$lock_dir/metadata.env" | head -n 1)"
    lock_start="$(sed -n 's/^process_start=//p' "$lock_dir/metadata.env" | head -n 1)"
    self_start="$(process_start "$$" 2>/dev/null || true)"
    if [ "$lock_pid" = "$$" ] && [ -n "$self_start" ] && [ "$lock_start" = "$self_start" ]; then
      # commit() is a compatibility wrapper around two typed operations.  The
      # same shell owns both phases, so taking the same lock is re-entrant.
      return 0
    fi
    if lock_owner_alive; then
      echo "adapter_busy=true"
      exit 75
    fi
    rm -f "$lock_dir/metadata.env"
    rmdir "$lock_dir" 2>/dev/null || {
      echo "reason=stale_lock_could_not_be_removed" >&2
      exit 75
    }
    mkdir "$lock_dir" 2>/dev/null || exit 75
  fi
  self_start="$(process_start "$$")"
  {
    echo "pid=$$"
    echo "process_start=$self_start"
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "created_at=$(now_utc)"
  } > "$lock_dir/metadata.env.tmp"
  mv "$lock_dir/metadata.env.tmp" "$lock_dir/metadata.env"
  trap release_lock EXIT
  trap 'exit 1' HUP INT TERM
}

valid_transaction_args() {
  printf '%s\n' "$txid" | grep -Eq '^tx_[0-9a-f]{16}$' || return 1
  printf '%s\n' "$revision" | grep -Eq '^rev_[0-9]+_[0-9a-f]{12}$' || return 1
  [ "$revision" != "rev-manual" ] || return 1
  [ "$config" = "$known_config" ] || return 1
}

require_transaction_args() {
  valid_transaction_args || {
    echo "reason=invalid_transaction_arguments" >&2
    exit 2
  }
  txdir="$txroot/$revision/$txid"
  candidate="$txdir/candidate.json"
  generated="$txdir/generated"
  binding_file="$txdir/binding.env"
  capability_file="$txdir/rollback.cap"
  timer_file="$timer_dir/$revision-$txid.env"
  # The command arguments are parsed at file scope.  Functions have their own
  # positional parameters in POSIX sh, so reading $5/$6 here silently dropped
  # the binding supplied by the caller and made a mismatched request look
  # valid.  Keep the parsed values in dedicated names instead.
  expected_candidate_hash="$recovery_candidate_hash"
  expected_artifact_manifest_hash="$recovery_artifact_manifest_hash"
}

load_recovery_args() {
  recovery_binding="$state/last-good/active-transaction.env"
  [ -f "$recovery_binding" ] || recovery_binding="$state/last-good/transaction.env"
  [ -f "$recovery_binding" ] || {
    echo "reason=last_good_binding_missing" >&2
    exit 3
  }
  [ -n "$txid" ] || txid="$(sed -n 's/^transaction_id=//p' "$recovery_binding" | head -n 1)"
  [ -n "$revision" ] || revision="$(sed -n 's/^revision_id=//p' "$recovery_binding" | head -n 1)"
  [ -n "$recovery_candidate_hash" ] || recovery_candidate_hash="$(sed -n 's/^candidate_hash=//p' "$recovery_binding" | head -n 1)"
  [ -n "$recovery_artifact_manifest_hash" ] || recovery_artifact_manifest_hash="$(sed -n 's/^artifact_manifest_hash=//p' "$recovery_binding" | head -n 1)"
}

require_recovery_args() {
  valid_transaction_args || {
    echo "reason=invalid_recovery_arguments" >&2
    exit 2
  }
  printf '%s\n' "$recovery_candidate_hash" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    echo "reason=invalid_recovery_candidate_hash" >&2
    exit 2
  }
  printf '%s\n' "$recovery_artifact_manifest_hash" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    echo "reason=invalid_recovery_artifact_hash" >&2
    exit 2
  }
}

delete_boot_guard_table() {
  # The runtime file is the ownership marker for this exact table.  Do not
  # hide nft failures: if FlintRoute believes it owns the guard, a failed
  # delete is a real reconcile error and must fence the transition.  A missing
  # table is an idempotent no-op.
  tables="$($nft_bin list tables 2>/dev/null)" || return 1
  printf '%s\n' "$tables" | grep -Eq '^table[[:space:]]+inet[[:space:]]+router_policy_boot_guard[[:space:]]*$' || return 0
  [ -f "$boot_guard_file" ] || {
    echo "reason=boot_guard_ownership_marker_missing" >&2
    return 1
  }
  current="$($nft_bin list table inet router_policy_boot_guard 2>/dev/null)" || return 1
  printf '%s\n' "$current" | grep -F 'comment "router-policy owner=flintroute"' >/dev/null || return 1
  "$nft_bin" delete table inet router_policy_boot_guard >/dev/null 2>&1 || return 1
  "$nft_bin" list table inet router_policy_boot_guard >/dev/null 2>&1 && return 1
  return 0
}

install_boot_guard() {
  mkdir -p "$runtime"
  {
    echo 'table inet router_policy_boot_guard {'
    echo '  comment "router-policy owner=flintroute"'
    echo '  chain forward {'
    # A mark-only guard would be fail-open after reboot: new flows have mark=0.
    # Drop all transit traffic until the exact committed generation is proven.
    # Run before the generated classifier (priority -5) and normal fw4 filter
    # chains.  A later accept must never be able to bypass the boot fence.
    echo '    type filter hook forward priority -300; policy drop;'
    echo '    counter comment "rp boot_guard action=drop_unclassified"'
    echo '  }'
    echo '}'
  } > "$boot_guard_file.tmp"
  mv "$boot_guard_file.tmp" "$boot_guard_file"
  replace_boot_guard_table
  echo "boot_guard=armed"
}

arm_transition_guard() {
  install_boot_guard
  echo "transition_guard=armed"
}

replace_boot_guard_table() {
  [ -s "$boot_guard_file" ] || return 1
  transition_batch="$runtime/nft-boot-guard-transition-${txid:-reconcile}.nft"
  mkdir -p "$runtime"
  existing_table=""
  if existing_table="$($nft_bin list table inet router_policy_boot_guard 2>/dev/null)"; then
    printf '%s\n' "$existing_table" | grep -F 'comment "router-policy owner=flintroute"' >/dev/null || {
      rm -f "$transition_batch"
      echo "reason=boot_guard_ownership_unproven" >&2
      return 1
    }
    printf '%s\n' 'delete table inet router_policy_boot_guard' > "$transition_batch"
  else
    : > "$transition_batch"
  fi
  cat "$boot_guard_file" >> "$transition_batch"
  if ! "$nft_bin" -c -f "$transition_batch"; then
    rm -f "$transition_batch"
    echo "reason=boot_guard_transition_check_failed" >&2
    return 1
  fi
  if ! "$nft_bin" -f "$transition_batch"; then
    rm -f "$transition_batch"
    echo "reason=boot_guard_transition_failed" >&2
    return 1
  fi
  rm -f "$transition_batch"
}

clear_boot_guard() {
  delete_boot_guard_table
  rm -f "$boot_guard_file"
  echo "boot_guard=cleared"
}

clear_boot_guard_bound() {
  require_transaction_args
  # The caller supplies the exact committed binding. Reuse the transaction
  # matcher so a stale generation can never remove the guard for a newer one.
  candidate_hash="$recovery_candidate_hash"
  artifact_manifest_hash="$recovery_artifact_manifest_hash"
  active_matches || {
    echo "reason=boot_guard_active_binding_mismatch" >&2
    return 1
  }
  [ "$(sed -n 's/^transaction_state=//p' "$active_file" | head -n 1)" = "committed" ] || {
    echo "reason=boot_guard_active_state_not_committed" >&2
    return 1
  }
  clear_boot_guard
  echo "operation=clear-boot-guard"
  echo "generation=$revision"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "active_transaction=$txid"
  echo "active_revision=$revision"
  echo "active_candidate_hash=$candidate_hash"
  echo "active_artifact_manifest_hash=$artifact_manifest_hash"
  echo "transaction_state=committed"
}

sha_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

file_mode_bits() {
  target="$1"
  # Transaction paths are fixed and allowlisted. BusyBox ls is available on
  # factory OpenWrt while a standalone stat binary is not guaranteed.
  # shellcheck disable=SC2012
  permissions="$(LC_ALL=C ls -ld "$target" 2>/dev/null | awk '{print substr($1, 1, 10)}')"
  case "$permissions" in
    -rw-------) echo 600 ;;
    -rw-r--r--) echo 644 ;;
    -rwx------) echo 700 ;;
    -rwxr-xr-x) echo 755 ;;
    drwx------) echo 700 ;;
    drwxr-xr-x) echo 755 ;;
    *) return 1 ;;
  esac
}

file_owner_id() {
  target="$1"
  # shellcheck disable=SC2012
  LC_ALL=C ls -ldn "$target" 2>/dev/null | awk '{print $3}'
}

verify_token() {
  [ -f "$binding_file" ] && [ -f "$capability_file" ] && [ ! -L "$capability_file" ] || {
    echo "reason=transaction_metadata_missing" >&2
    return 1
  }
  capability_mode="$(file_mode_bits "$capability_file")"
  capability_owner="$(file_owner_id "$capability_file")"
  tx_owner="$(file_owner_id "$txdir")"
  [ -n "$capability_owner" ] && [ -n "$tx_owner" ] || {
    echo "reason=rollback_capability_owner_unavailable" >&2
    return 1
  }
  [ "$capability_mode" = "600" ] && [ "$capability_owner" = "$tx_owner" ] || {
    echo "reason=rollback_capability_permissions_invalid" >&2
    return 1
  }
  stored_tx="$(sed -n 's/^transaction_id=//p' "$binding_file" | head -n 1)"
  stored_revision="$(sed -n 's/^revision_id=//p' "$binding_file" | head -n 1)"
  stored_hash="$(sed -n 's/^rollback_token_hash=//p' "$binding_file" | head -n 1)"
  candidate_hash="$(sed -n 's/^candidate_hash=//p' "$binding_file" | head -n 1)"
  artifact_manifest_hash="$(sed -n 's/^artifact_manifest_hash=//p' "$binding_file" | head -n 1)"
  artifacts_ready="$(sed -n 's/^artifacts_ready=//p' "$binding_file" | head -n 1)"
  artifact_block_reason="$(sed -n 's/^artifact_block_reason=//p' "$binding_file" | head -n 1)"
  artifacts_simulation="$(sed -n 's/^artifacts_simulation=//p' "$binding_file" | head -n 1)"
  [ "$stored_tx" = "$txid" ] && [ "$stored_revision" = "$revision" ] && [ -n "$candidate_hash" ] && [ -n "$artifact_manifest_hash" ] || {
    echo "reason=transaction_identity_mismatch" >&2
    return 1
  }
  if [ -n "${expected_candidate_hash:-}" ] && [ "$expected_candidate_hash" != "$candidate_hash" ]; then
    echo "reason=candidate_hash_binding_mismatch" >&2
    return 1
  fi
  if [ -n "${expected_artifact_manifest_hash:-}" ] && [ "$expected_artifact_manifest_hash" != "$artifact_manifest_hash" ]; then
    echo "reason=artifact_manifest_hash_binding_mismatch" >&2
    return 1
  fi
  case "$artifacts_ready" in true|false) ;; *) echo "reason=artifact_readiness_missing" >&2; return 1 ;; esac
  case "$artifacts_simulation" in true|false) ;; *) echo "reason=artifact_simulation_flag_missing" >&2; return 1 ;; esac
  "$router_policy_bin" internal-verify-rollback-token "$stored_hash" < "$capability_file" >/dev/null 2>&1 || {
    echo "reason=rollback_token_invalid" >&2
    return 1
  }
}

write_status() {
  status_value="$1"
  mkdir -p "$txdir"
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "status=$status_value"
    echo "transaction_state=$status_value"
    echo "updated_at=$(now_utc)"
  } > "$txdir/status.env.tmp"
  mv "$txdir/status.env.tmp" "$txdir/status.env"
}

pending_matches() {
  [ -f "$pending_file" ] || return 1
  pending_tx="$(sed -n 's/^transaction_id=//p' "$pending_file" | head -n 1)"
  pending_revision="$(sed -n 's/^revision_id=//p' "$pending_file" | head -n 1)"
  [ "$pending_tx" = "$txid" ] && [ "$pending_revision" = "$revision" ]
}

claim_pending() {
  if [ -f "$pending_file" ] && ! pending_matches; then
    echo "reason=another_transaction_is_pending" >&2
    exit 75
  fi
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "created_at=$(now_utc)"
  } > "$pending_file.tmp"
  mv "$pending_file.tmp" "$pending_file"
}

prepare_tx() {
  take_lock
  claim_pending
  mkdir -p "$txdir/snapshot"
  verify_token
  [ -f "$candidate" ] || {
    echo "reason=candidate_config_missing" >&2
    exit 3
  }
  [ -f "$generated/manifest.json" ] && [ -f "$generated/manifest.sha256" ] || {
    echo "reason=generated_artifacts_missing" >&2
    exit 3
  }
  write_status "prepared"
  echo "prepared=true"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
}

profile_id_valid() {
  printf '%s\n' "$1" | grep -Eq '^[a-z][a-z0-9-]{0,31}$'
}

profile_entry_validate() {
  profile_id="$1"
  profile_config="$2"
  profile_init="$3"
  profile_queue="$4"
  profile_id_valid "$profile_id" || return 1
  [ "$profile_config" = "$zapret_profile_dir/$profile_id.conf" ] || return 1
  [ "$profile_init" = "$zapret_profile_init_prefix$profile_id" ] || return 1
  printf '%s\n' "$profile_queue" | grep -Eq '^[0-9]+$' || return 1
  [ "$profile_queue" -ge 2 ] && [ "$profile_queue" -le 65535 ]
}

profile_manifest_validate() {
  profile_manifest="$1"
  [ -e "$profile_manifest" ] || return 0
  [ -f "$profile_manifest" ] && [ ! -L "$profile_manifest" ] || return 1
  profile_seen=" "
  while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
    [ -z "${profile_id:-}" ] && continue
    [ -z "${profile_extra:-}" ] || return 1
    profile_entry_validate "$profile_id" "$profile_config" "$profile_init" "$profile_queue" || return 1
    case "$profile_seen" in
      *" $profile_id "*) return 1 ;;
    esac
    profile_seen="$profile_seen$profile_id "
  done < "$profile_manifest"
}

profile_source_config() {
  printf '%s\n' "$generated/zapret-profile-$1.conf"
}

profile_artifact_config() {
  printf '%s\n' "$1/zapret-profile-$2.conf"
}

profile_source_service() {
  printf '%s\n' "$generated/zapret-service-$1"
}

profile_artifact_service() {
  printf '%s\n' "$1/zapret-service-$2"
}

stop_profile_services() {
  profile_manifest="$1"
  [ -f "$profile_manifest" ] || return 0
  profile_manifest_validate "$profile_manifest" || {
    echo "reason=profile_manifest_invalid" >&2
    return 1
  }
  while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
    [ -z "${profile_id:-}" ] && continue
    stop_managed_service "$profile_init"
  done < "$profile_manifest"
}

remove_profile_resources() {
  profile_manifest="$1"
  [ -f "$profile_manifest" ] || return 0
  profile_manifest_validate "$profile_manifest" || {
    echo "reason=profile_manifest_invalid" >&2
    return 1
  }
  while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
    [ -z "${profile_id:-}" ] && continue
    rm -f "$profile_config" "$profile_init"
  done < "$profile_manifest"
}

install_profile_artifacts() {
  install_manifest="$1"
  [ -f "$install_manifest" ] || {
    echo "reason=profile_manifest_missing" >&2
    return 1
  }
  profile_manifest_validate "$install_manifest" || {
    echo "reason=profile_manifest_invalid" >&2
    return 1
  }
  stop_profile_services "$active_zapret_profiles"
  remove_profile_resources "$active_zapret_profiles"
  if [ -s "$install_manifest" ]; then
    mkdir -p "$zapret_profile_dir"
  fi
  while IFS='|' read -r install_profile_id install_profile_config install_profile_init _ _; do
    [ -z "${install_profile_id:-}" ] && continue
    profile_source_config_path="$(profile_source_config "$install_profile_id")"
    profile_source_service_path="$(profile_source_service "$install_profile_id")"
    [ -s "$profile_source_config_path" ] && [ -f "$profile_source_service_path" ] || {
      echo "reason=profile_artifact_missing" >&2
      return 1
    }
    atomic_install "$profile_source_config_path" "$install_profile_config"
    atomic_install "$profile_source_service_path" "$install_profile_init"
    chmod 755 "$install_profile_init"
  done < "$install_manifest"
  atomic_install "$install_manifest" "$active_zapret_profiles"
}

start_profile_services() {
  profile_manifest="$1"
  [ -f "$profile_manifest" ] || return 0
  profile_manifest_validate "$profile_manifest" || {
    echo "reason=profile_manifest_invalid" >&2
    return 1
  }
  while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
    [ -z "${profile_id:-}" ] && continue
    start_managed_service "$profile_init" "router-policy-zapret-$profile_id"
  done < "$profile_manifest"
}

snapshot_one() {
  snapshot_target="$1"
  snapshot_name="$2"
  snapshot_output="$3"
  if [ -e "$snapshot_target" ]; then
    [ -f "$snapshot_target" ] || {
      echo "reason=snapshot_target_not_regular_file" >&2
      return 1
    }
    cp "$snapshot_target" "$snapshot_output/$snapshot_name"
    snapshot_hash="$(sha_file "$snapshot_output/$snapshot_name")"
    snapshot_bytes="$(wc -c < "$snapshot_output/$snapshot_name" | tr -d ' ')"
    echo "$snapshot_target|present|$snapshot_name|$snapshot_bytes|sha256:$snapshot_hash|project" >> "$snapshot_output/manifest.txt"
  else
    printf '%s\n' "$snapshot_target" > "$snapshot_output/$snapshot_name.absent"
    echo "$snapshot_target|absent|$snapshot_name|0|-|project" >> "$snapshot_output/manifest.txt"
  fi
}

snapshot_source_as() {
  snapshot_target="$1"
  snapshot_name="$2"
  snapshot_output="$3"
  snapshot_source="$4"
  [ -f "$snapshot_source" ] && [ ! -L "$snapshot_source" ] || {
    echo "reason=snapshot_source_not_regular_file" >&2
    return 1
  }
  cp "$snapshot_source" "$snapshot_output/$snapshot_name"
  snapshot_hash="$(sha_file "$snapshot_output/$snapshot_name")"
  snapshot_bytes="$(wc -c < "$snapshot_output/$snapshot_name" | tr -d ' ')"
  echo "$snapshot_target|present|$snapshot_name|$snapshot_bytes|sha256:$snapshot_hash|project" >> "$snapshot_output/manifest.txt"
}

snapshot_uci_one() {
  snapshot_key="$1"
  snapshot_name="$2"
  snapshot_output="$3"
  snapshot_target="uci:$snapshot_key"
  if snapshot_value="$("$uci_bin" -q get "$snapshot_key" 2>/dev/null)"; then
    case "$snapshot_value" in
      0|1) ;;
      *)
        echo "reason=invalid_flow_offloading_uci_value" >&2
        return 1
        ;;
    esac
    printf '%s\n' "$snapshot_value" > "$snapshot_output/$snapshot_name"
    snapshot_hash="$(sha_file "$snapshot_output/$snapshot_name")"
    snapshot_bytes="$(wc -c < "$snapshot_output/$snapshot_name" | tr -d ' ')"
    echo "$snapshot_target|present|$snapshot_name|$snapshot_bytes|sha256:$snapshot_hash|openwrt-uci" >> "$snapshot_output/manifest.txt"
  else
    printf '%s\n' "$snapshot_target" > "$snapshot_output/$snapshot_name.absent"
    echo "$snapshot_target|absent|$snapshot_name|0|-|openwrt-uci" >> "$snapshot_output/manifest.txt"
  fi
}

snapshot_service_one() {
  snapshot_init="$1"
  snapshot_name="$2"
  snapshot_output="$3"
  snapshot_target="service:$snapshot_init"
  snapshot_value="stopped"
  if [ -x "$snapshot_init" ] && "$snapshot_init" running >/dev/null 2>&1; then
    snapshot_value="running"
  fi
  printf '%s\n' "$snapshot_value" > "$snapshot_output/$snapshot_name"
  snapshot_hash="$(sha_file "$snapshot_output/$snapshot_name")"
  snapshot_bytes="$(wc -c < "$snapshot_output/$snapshot_name" | tr -d ' ')"
  echo "$snapshot_target|present|$snapshot_name|$snapshot_bytes|sha256:$snapshot_hash|project-service" >> "$snapshot_output/manifest.txt"
}

snapshot_profile_resources() {
  profile_manifest="$1"
  snapshot_output="$2"
  [ -f "$profile_manifest" ] || return 0
  profile_manifest_validate "$profile_manifest" || {
    echo "reason=profile_manifest_invalid" >&2
    return 1
  }
  while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
    [ -z "${profile_id:-}" ] && continue
    snapshot_one "$profile_config" "profile-$profile_id.conf" "$snapshot_output"
    snapshot_service_one "$profile_init" "profile-$profile_id.service.state" "$snapshot_output"
  done < "$profile_manifest"
}

ensure_flow_offload_baseline() {
  if [ -e "$ownership_dir" ]; then
    [ -d "$ownership_dir" ] && [ ! -L "$ownership_dir" ] || {
      echo "reason=flow_offloading_ownership_dir_invalid" >&2
      return 1
    }
  else
    mkdir -p "$ownership_dir"
  fi
  chmod 700 "$ownership_dir"
  if [ -e "$flow_offload_baseline" ]; then
    [ -f "$flow_offload_baseline" ] && [ ! -L "$flow_offload_baseline" ] || {
      echo "reason=flow_offloading_baseline_not_regular" >&2
      return 1
    }
    baseline_mode="$(file_mode_bits "$flow_offload_baseline")"
    baseline_owner="$(file_owner_id "$flow_offload_baseline")"
    ownership_owner="$(file_owner_id "$ownership_dir")"
    [ "$baseline_mode" = 600 ] && [ -n "$baseline_owner" ] && [ "$baseline_owner" = "$ownership_owner" ] || {
      echo "reason=flow_offloading_baseline_permissions_invalid" >&2
      return 1
    }
    baseline_schema="$(sed -n 's/^schema_version=//p' "$flow_offload_baseline" | head -n 1)"
    baseline_software="$(sed -n 's/^software=//p' "$flow_offload_baseline" | head -n 1)"
    baseline_hardware="$(sed -n 's/^hardware=//p' "$flow_offload_baseline" | head -n 1)"
    [ "$baseline_schema" = 1 ] || { echo "reason=flow_offloading_baseline_schema_invalid" >&2; return 1; }
    case "$baseline_software:$baseline_hardware" in
      0:0|0:1|0:absent|1:0|1:1|1:absent|absent:0|absent:1|absent:absent) return 0 ;;
      *) echo "reason=flow_offloading_baseline_value_invalid" >&2; return 1 ;;
    esac
  fi
  if ! baseline_software="$("$uci_bin" -q get "$flow_offload_uci_key" 2>/dev/null)"; then
    baseline_software=absent
  fi
  if ! baseline_hardware="$("$uci_bin" -q get "$flow_offload_hw_uci_key" 2>/dev/null)"; then
    baseline_hardware=absent
  fi
  case "$baseline_software:$baseline_hardware" in
    0:0|0:1|0:absent|1:0|1:1|1:absent|absent:0|absent:1|absent:absent) ;;
    *) echo "reason=flow_offloading_baseline_value_invalid" >&2; return 1 ;;
  esac
  rm -f "$flow_offload_baseline.tmp"
  {
    echo "schema_version=1"
    echo "software=$baseline_software"
    echo "hardware=$baseline_hardware"
    echo "recorded_at=$(now_utc)"
  } >"$flow_offload_baseline.tmp"
  chmod 600 "$flow_offload_baseline.tmp"
  mv "$flow_offload_baseline.tmp" "$flow_offload_baseline"
  baseline_bytes="$(wc -c <"$flow_offload_baseline" | tr -d ' ')"
  record_runtime_write_event "file_created" "$baseline_bytes" "openwrt_ownership_baseline"
}

create_snapshot() {
  create_root="$1"
  committed_active_source="${2:-}"
  recovery_artifact_source="${3:-}"
  committed_config_source="${4:-}"
  rm -rf "$create_root.tmp"
  mkdir -p "$create_root.tmp"
  : > "$create_root.tmp/manifest.txt"
  if [ -n "$committed_config_source" ]; then
    snapshot_source_as "$config" "router-policy-config.json" "$create_root.tmp" "$committed_config_source"
  else
    snapshot_one "$config" "router-policy-config.json" "$create_root.tmp"
  fi
  snapshot_one "$active_nft" "router-policy.nft" "$create_root.tmp"
  snapshot_one "$active_dnsmasq" "router-policy-dnsmasq.conf" "$create_root.tmp"
  snapshot_one "$active_xray" "xray-active.json" "$create_root.tmp"
  snapshot_one "$active_zapret" "nfqws.conf" "$create_root.tmp"
  snapshot_one "$active_zapret_profiles" "zapret-profiles.manifest" "$create_root.tmp"
  snapshot_profile_resources "$active_zapret_profiles" "$create_root.tmp"
  snapshot_service_one "$xray_init" "xray-service.state" "$create_root.tmp"
  snapshot_service_one "$zapret_init" "zapret-service.state" "$create_root.tmp"
  snapshot_uci_one "$flow_offload_uci_key" "flow-offloading.uci" "$create_root.tmp"
  snapshot_uci_one "$flow_offload_hw_uci_key" "flow-offloading-hw.uci" "$create_root.tmp"
  if [ -n "$committed_active_source" ]; then
    snapshot_source_as "$active_file" "active-transaction.env" "$create_root.tmp" "$committed_active_source"
  else
    snapshot_one "$active_file" "active-transaction.env" "$create_root.tmp"
  fi
  if [ -n "$recovery_artifact_source" ]; then
    [ -d "$recovery_artifact_source" ] && [ ! -L "$recovery_artifact_source" ] || {
      echo "reason=recovery_artifact_source_invalid" >&2
      return 1
    }
    cp -R "$recovery_artifact_source" "$create_root.tmp/generated"
  fi
  sha_file "$create_root.tmp/manifest.txt" > "$create_root.tmp/manifest.sha256"
  verify_snapshot "$create_root.tmp" || { echo "reason=new_snapshot_integrity_failed" >&2; return 1; }
  previous="$create_root.previous"
  rm -rf "$previous"
  if [ -d "$create_root" ] && [ ! -L "$create_root" ]; then
    mv "$create_root" "$previous"
  fi
  if ! mv "$create_root.tmp" "$create_root" || ! verify_snapshot "$create_root"; then
    rm -rf "$create_root"
    [ ! -d "$previous" ] || mv "$previous" "$create_root"
    echo "reason=snapshot_activation_failed" >&2
    return 1
  fi
  rm -rf "$previous"
  record_runtime_write_event "snapshot" "0" "transaction_snapshot"
}

snapshot_current() {
  take_lock
  verify_token
  pending_matches || {
    echo "reason=transaction_not_pending" >&2
    exit 3
  }
  ensure_flow_offload_baseline
  create_snapshot "$txdir/snapshot"
  if [ -f "$generated/ip-plan.json" ]; then
    if ROUTER_POLICY_IP_BIN="$ip_bin" "$router_policy_bin" internal-snapshot-ip-state --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --out "$txdir/snapshot/ip-state.json" >/dev/null 2>&1; then
      printf '%s\n' "sha256:$(sha_file "$txdir/snapshot/ip-state.json")" > "$txdir/snapshot/ip-state.sha256"
    else
      echo "reason=ip_state_snapshot_failed" >&2
      exit 3
    fi
  fi
  write_status "snapshotted"
  echo "snapshot_ok=true"
}

validate_candidate() {
  take_lock
  verify_token
  pending_matches || exit 3
  [ -s "$candidate" ] || {
    echo "reason=candidate_config_empty" >&2
    exit 3
  }
  "$router_policy_bin" internal-verify-candidate --candidate "$candidate" --candidate-hash "$candidate_hash" >/dev/null
  ROUTER_POLICY_CONFIG="$candidate" "$router_policy_bin" validate-config >/dev/null
  "$router_policy_bin" internal-verify-artifacts --root "$generated" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --manifest-hash "$artifact_manifest_hash" >/dev/null
  "$nft_bin" -c -f "$generated/router-policy.nft"
  verify_dnsmasq_include_target
  "$dnsmasq_bin" --test --conf-file="$generated/router-policy-dnsmasq.conf" >/dev/null
  "$xray_bin" run -test -config "$generated/xray.json" >/dev/null
  ip_plan_status="$("$router_policy_bin" internal-validate-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash")"
  printf '%s\n' "$ip_plan_status"
  plan_ready=
  plan_reason=
  plan_simulation=
  plan_xray_enabled=
  plan_xray_managed=
  plan_zapret_enabled=
  plan_zapret_managed=
  while IFS='=' read -r plan_key plan_value; do
    case "$plan_key" in
      deployment_ready) plan_ready="$plan_value" ;;
      reason) plan_reason="$plan_value" ;;
      simulation) plan_simulation="$plan_value" ;;
      xray_enabled) plan_xray_enabled="$plan_value" ;;
      xray_managed) plan_xray_managed="$plan_value" ;;
      zapret_enabled) plan_zapret_enabled="$plan_value" ;;
      zapret_managed) plan_zapret_managed="$plan_value" ;;
    esac
  done <<EOF
$ip_plan_status
EOF
  [ "$plan_xray_enabled" = "true" ] || [ "$plan_xray_managed" = "false" ] || {
    echo "reason=invalid_xray_service_plan" >&2
    exit 3
  }
  [ "$plan_zapret_enabled" = "true" ] || [ "$plan_zapret_managed" = "false" ] || {
    echo "reason=invalid_zapret_service_plan" >&2
    exit 3
  }
  [ "$plan_ready" = "$artifacts_ready" ] && [ "$plan_reason" = "$artifact_block_reason" ] && [ "$plan_simulation" = "$artifacts_simulation" ] || {
    echo "reason=artifact_readiness_binding_mismatch" >&2
    exit 3
  }
  if printf '%s\n' "$ip_plan_status" | grep -q '^deployment_ready=false$'; then
    write_status "candidate_requires_device"
    echo "candidate_valid=false"
    echo "verification_status=UNVERIFIED"
    return 0
  fi
  if [ "$plan_simulation" = "true" ] && [ "${ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS:-0}" != "1" ]; then
    write_status "candidate_requires_device"
    echo "candidate_valid=false"
    echo "verification_status=UNVERIFIED"
    echo "reason=simulated_diagnostics_refused"
    return 0
  fi
  if [ "$plan_zapret_enabled" = "true" ]; then
    [ -x "$nfqws_bin" ] && [ -s "$generated/nfqws.conf" ] || {
      echo "reason=nfqws_not_installed" >&2
      exit 3
    }
    zapret_check="$txdir/nfqws-check.conf"
    cp "$generated/nfqws.conf" "$zapret_check"
    printf '%s\n' '--dry-run' >> "$zapret_check"
    if ! "$nfqws_bin" "@$zapret_check" >/dev/null; then
      rm -f "$zapret_check"
      echo "reason=nfqws_candidate_invalid" >&2
      exit 3
    fi
    rm -f "$zapret_check"
  fi
  if [ -f "$generated/zapret-profiles.manifest" ]; then
    profile_manifest_validate "$generated/zapret-profiles.manifest" || {
      echo "reason=profile_manifest_invalid" >&2
      exit 3
    }
    while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
      [ -z "${profile_id:-}" ] && continue
      profile_check="$(profile_source_config "$profile_id").check"
      cp "$(profile_source_config "$profile_id")" "$profile_check"
      printf '%s\n' '--dry-run' >> "$profile_check"
      if ! "$nfqws_bin" "@$profile_check" >/dev/null; then
        rm -f "$profile_check"
        echo "reason=device_profile_candidate_invalid" >&2
        exit 3
      fi
      rm -f "$profile_check"
      [ -s "$(profile_source_service "$profile_id")" ] || {
        echo "reason=device_profile_service_missing" >&2
        exit 3
      }
    done < "$generated/zapret-profiles.manifest"
  fi
  if [ "$plan_xray_managed" = "true" ] && [ ! -x "$xray_init" ]; then
    echo "reason=xray_init_missing" >&2
    exit 3
  fi
  if [ "$plan_zapret_managed" = "true" ] && [ ! -x "$zapret_init" ]; then
    echo "reason=zapret_init_missing" >&2
    exit 3
  fi
  write_status "candidate_validated"
  echo "candidate_valid=true"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

rollback_timeout() {
  value="$(sed -n 's/^rollback_timeout_seconds=//p' "$binding_file" 2>/dev/null | head -n 1)"
  # The binding is the typed transaction contract.  Never parse candidate JSON
  # in shell: formatting changes must not alter the rollback safety decision.
  if ! printf '%s\n' "$value" | grep -Eq '^[0-9]+$' || [ "$value" -lt 1 ] || [ "$value" -gt 3600 ]; then
    value=120
  fi
  echo "$value"
}

start_timer() {
  seconds="$(rollback_timeout)"
  timer_bootstrap="$timer_file.bootstrap"
  rm -f "$timer_bootstrap" "$timer_bootstrap.tmp"
  (
    sleeper_pid=""
    # The worker owns this child. Keep the trap active until the child has
    # exited so a startup failure cannot strand a sleep process under PID 1.
    trap 'if [ -n "$sleeper_pid" ]; then kill -TERM "$sleeper_pid" 2>/dev/null || true; fi; exit 143' HUP INT TERM
    sleep "$seconds" &
    sleeper_pid="$!"
    sleeper_start="$(process_start "$sleeper_pid")"
    {
      echo "sleep_pid=$sleeper_pid"
      echo "sleep_process_start=$sleeper_start"
    } > "$timer_bootstrap.tmp"
    mv "$timer_bootstrap.tmp" "$timer_bootstrap"
    wait "$sleeper_pid" || exit 0
    if [ -f "$timer_file" ]; then
      timer_tx="$(sed -n 's/^transaction_id=//p' "$timer_file" | head -n 1)"
      timer_revision="$(sed -n 's/^revision_id=//p' "$timer_file" | head -n 1)"
      if [ "$timer_tx" = "$txid" ] && [ "$timer_revision" = "$revision" ]; then
        ROLLBACK_TIMER_FIRED=1 "$adapter_self" rollback "$config" "$txid" "$revision"
      fi
    fi
  ) </dev/null >/dev/null 2>&1 &
  timer_pid="$!"
  timer_start="$(process_start "$timer_pid")"
  timer_wait_attempts=0
  while [ ! -f "$timer_bootstrap" ]; do
    timer_wait_attempts=$((timer_wait_attempts + 1))
    [ "$timer_wait_attempts" -le 5 ] || {
      # Do not use an unbound kill here: a reused PID must never be stopped.
      # If the worker did not publish its child identity, we can only prove
      # ownership of the worker itself; failure to terminate it is a hard
      # start failure rather than permission to leave an orphan timer behind.
      terminate_owned_timer_pid "$timer_pid" "$timer_start" || {
        echo "reason=rollback_timer_worker_cleanup_unverified" >&2
        return 1
      }
      rm -f "$timer_bootstrap" "$timer_bootstrap.tmp"
      echo "reason=rollback_timer_failed_to_start" >&2
      return 1
    }
    sleep 1
  done
  timer_sleep_pid="$(sed -n 's/^sleep_pid=//p' "$timer_bootstrap" | head -n 1)"
  timer_sleep_start="$(sed -n 's/^sleep_process_start=//p' "$timer_bootstrap" | head -n 1)"
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "pid=$timer_pid"
    echo "process_start=$timer_start"
    echo "sleep_pid=$timer_sleep_pid"
    echo "sleep_process_start=$timer_sleep_start"
    echo "expires_at_seconds=$seconds"
    echo "created_at=$(now_utc)"
  } > "$timer_file.tmp"
  mv "$timer_file.tmp" "$timer_file"
  rm -f "$timer_bootstrap"
}

cancel_timer() {
  [ -f "$timer_file" ] || return 0
  timer_tx="$(sed -n 's/^transaction_id=//p' "$timer_file" | head -n 1)"
  timer_revision="$(sed -n 's/^revision_id=//p' "$timer_file" | head -n 1)"
  timer_pid="$(sed -n 's/^pid=//p' "$timer_file" | head -n 1)"
  timer_start="$(sed -n 's/^process_start=//p' "$timer_file" | head -n 1)"
  timer_sleep_pid="$(sed -n 's/^sleep_pid=//p' "$timer_file" | head -n 1)"
  timer_sleep_start="$(sed -n 's/^sleep_process_start=//p' "$timer_file" | head -n 1)"
  [ "$timer_tx" = "$txid" ] && [ "$timer_revision" = "$revision" ] || {
    echo "reason=timer_identity_mismatch" >&2
    return 1
  }
  if [ "${ROLLBACK_TIMER_FIRED:-0}" = "1" ]; then
    rm -f "$timer_file"
    return 0
  fi
  if [ -n "$timer_sleep_pid" ] && [ -n "$timer_sleep_start" ]; then
    terminate_owned_timer_pid "$timer_sleep_pid" "$timer_sleep_start" || return 1
  fi
  if [ -n "$timer_pid" ] && [ -n "$timer_start" ]; then
    terminate_owned_timer_pid "$timer_pid" "$timer_start" || return 1
  fi
  rm -f "$timer_file" "$timer_file.bootstrap" "$timer_file.bootstrap.tmp"
}

atomic_install() {
  install_source="$1"
  install_target="$2"
  [ ! -L "$install_target" ] || { echo "reason=refusing_symlink_install_target" >&2; return 1; }
  install_mode="$(file_mode_bits "$install_source")"
  install_event="file_created"
  [ ! -f "$install_target" ] || install_event="file_replaced"
  if [ -f "$install_target" ] && cmp -s "$install_source" "$install_target"; then
    target_mode="$(file_mode_bits "$install_target")"
    if [ "$target_mode" = "$install_mode" ]; then
      return 0
    fi
  fi
  install_tmp="$(mktemp "$install_target.tmp.$txid.XXXXXX")"
  if ! cp "$install_source" "$install_tmp" || ! chmod "$install_mode" "$install_tmp"; then
    rm -f "$install_tmp"
    return 1
  fi
  if ! { sync -f "$install_tmp" 2>/dev/null || sync "$install_tmp" 2>/dev/null || sync; } || ! mv "$install_tmp" "$install_target"; then
    rm -f "$install_tmp"
    return 1
  fi
  install_bytes="$(wc -c < "$install_source" | tr -d ' ')"
  directory_sync_scope="exact"
  if ! sync -f "$(dirname "$install_target")" 2>/dev/null; then
    directory_sync_scope="global"
    if ! sync 2>/dev/null; then
      record_runtime_write_event "fsync_failed" "$install_bytes" "active_artifact_install_directory"
      return 1
    fi
  fi
  record_runtime_write_event "$install_event" "$install_bytes" "active_artifact_install"
  record_runtime_write_event "fsync" "2" "active_artifact_install"
  record_runtime_write_event "fsync_scope" "0" "active_artifact_install:$directory_sync_scope"
}

nft_identity() {
  identity_file="$1"
  [ -s "$identity_file" ] || return 1
  identity="$(sed -n 's/^table[[:space:]]\+\([a-z0-9_][a-z0-9_]*\)[[:space:]]\+\([A-Za-z0-9_][A-Za-z0-9_]*\)[[:space:]]*{[[:space:]]*$/\1 \2/p' "$identity_file" | head -n 1)"
  identity_family="${identity%% *}"
  identity_table="${identity#* }"
  [ "$identity" = "$identity_family $identity_table" ] || return 1
  [ "$identity_family" = "inet" ] || return 1
  printf '%s\n' "$identity_table" | grep -Eq '^[A-Za-z0-9_]+$' || return 1
  printf '%s %s\n' "$identity_family" "$identity_table"
}

replace_owned_nft_table() {
  nft_source="$1"
  [ -s "$nft_source" ] || return 0
  if ! identity="$(nft_identity "$nft_source" 2>/dev/null)"; then
    echo "reason=owned_nft_identity_invalid" >&2
    return 1
  fi
  [ -n "$identity" ] || {
    echo "reason=owned_nft_identity_invalid" >&2
    return 1
  }
  identity_family="${identity%% *}"
  identity_table="${identity#* }"
  owned_marker='comment "router-policy owner=flintroute"'
  grep -F "$owned_marker" "$nft_source" >/dev/null || {
    echo "reason=owned_nft_marker_missing" >&2
    return 1
  }
  transition_batch="$runtime/nft-transition-${txid:-reconcile}.nft"
  mkdir -p "$runtime"
  # A single nft input is one kernel transaction.  If the owned table exists,
  # destroy and recreate it in that same transaction; syntax or apply errors
  # therefore leave the previous table intact instead of opening a gap.
  existing_table=""
  if existing_table="$("$nft_bin" list table "$identity_family" "$identity_table" 2>/dev/null)"; then
    printf '%s\n' "$existing_table" | grep -F "$owned_marker" >/dev/null || {
      rm -f "$transition_batch"
      echo "reason=owned_nft_ownership_unproven" >&2
      return 1
    }
    printf 'delete table %s %s\n' "$identity_family" "$identity_table" > "$transition_batch"
  else
    : > "$transition_batch"
  fi
  cat "$nft_source" >> "$transition_batch"
  if ! "$nft_bin" -c -f "$transition_batch"; then
    rm -f "$transition_batch"
    echo "reason=owned_nft_transition_check_failed" >&2
    return 1
  fi
  if ! "$nft_bin" -f "$transition_batch"; then
    rm -f "$transition_batch"
    echo "reason=owned_nft_transition_failed" >&2
    return 1
  fi
  rm -f "$transition_batch"
}

reload_project_firewall() {
  if [ -s "$active_nft" ]; then
    replace_owned_nft_table "$active_nft"
  fi
}

replace_owned_nft_command() {
  take_lock
  verify_token
  pending_matches || { echo "reason=transaction_not_pending" >&2; exit 3; }
  replace_owned_nft_table "$generated/router-policy.nft"
  echo "operation=nft.replace_owned_table"
  echo "generation=$revision"
  echo "transaction_state=nft_replaced"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

apply_ip_plan_command() {
  take_lock
  verify_token
  pending_matches || { echo "reason=transaction_not_pending" >&2; exit 3; }
  [ -f "$generated/ip-plan.json" ] || { echo "reason=ip_plan_missing" >&2; exit 3; }
  ROUTER_POLICY_IP_BIN="$ip_bin" ROUTER_POLICY_UCI_BIN="$uci_bin" "$router_policy_bin" internal-apply-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" >/dev/null
  echo "operation=ip_plan.apply"
  echo "generation=$revision"
  echo "transaction_state=ip_plan_applied"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

rollback_ip_plan_command() {
  take_lock
  verify_token
  pending_matches || { echo "reason=transaction_not_pending" >&2; exit 3; }
  [ -f "$generated/ip-plan.json" ] && [ -f "$txdir/snapshot/ip-state.json" ] || { echo "reason=ip_plan_snapshot_missing" >&2; exit 3; }
  ROUTER_POLICY_IP_BIN="$ip_bin" "$router_policy_bin" internal-rollback-ip-state --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --pre-state "$txdir/snapshot/ip-state.json" >/dev/null
  echo "operation=ip_plan.rollback"
  echo "generation=$revision"
  echo "transaction_state=ip_plan_rolled_back"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

artifact_paths() {
  helper_artifact_kind="$1"
  case "$helper_artifact_kind" in
    xray_config) artifact_source="$generated/xray.json"; artifact_target="$active_xray" ;;
    zapret_config) artifact_source="$generated/nfqws.conf"; artifact_target="$active_zapret" ;;
    zapret_profile_manifest) artifact_source="$generated/zapret-profiles.manifest"; artifact_target="$active_zapret_profiles" ;;
    dnsmasq_config) artifact_source="$generated/router-policy-dnsmasq.conf"; artifact_target="$active_dnsmasq" ;;
    nft_table) artifact_source="$generated/router-policy.nft"; artifact_target="$active_nft" ;;
    ip_plan) artifact_source="$generated/ip-plan.json"; artifact_target="$txdir/active-ip-plan.json" ;;
    *) echo "reason=artifact_kind_not_allowlisted" >&2; return 1 ;;
  esac
}

install_artifact_command() {
  take_lock
  verify_token
  pending_matches || { echo "reason=transaction_not_pending" >&2; exit 3; }
  artifact_paths "${7:-}" || exit 2
  [ -f "$artifact_source" ] && [ ! -L "$artifact_source" ] || { echo "reason=artifact_source_missing" >&2; exit 3; }
  if [ "${7:-}" = "nft_table" ]; then
    replace_owned_nft_table "$artifact_source"
  else
    atomic_install "$artifact_source" "$artifact_target"
  fi
  echo "operation=artifact.install"
  echo "generation=$revision"
  echo "transaction_state=artifact_installed"
  echo "artifact_kind=${7:-}"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

remove_artifact_command() {
  take_lock
  verify_token
  pending_matches || { echo "reason=transaction_not_pending" >&2; exit 3; }
  artifact_paths "${7:-}" || exit 2
  [ "${7:-}" != "nft_table" ] || { echo "reason=nft_table_requires_owned_transition" >&2; exit 3; }
  rm -f "$artifact_target"
  echo "operation=artifact.remove"
  echo "generation=$revision"
  echo "transaction_state=artifact_removed"
  echo "artifact_kind=${7:-}"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

wait_dnsmasq_ready() {
  attempts=0
  while ! "$nslookup_bin" localhost 127.0.0.1 >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 15 ]; then
      echo "reason=dnsmasq_not_ready" >&2
      return 1
    fi
    sleep 1
  done
}

ensure_dns_observation_log() {
  configured_log="$(sed -n 's/^log-facility=//p' "$active_dnsmasq" 2>/dev/null | head -n 1)"
  [ -n "$configured_log" ] || return 0
  expected_log="$dns_observation_log"
  if command -v cygpath >/dev/null 2>&1; then
    configured_log="$(cygpath -m "$configured_log")"
    expected_log="$(cygpath -m "$expected_log")"
  fi
  [ "$configured_log" = "$expected_log" ] || {
    echo "reason=dns_observation_log_outside_runtime" >&2
    return 1
  }
  [ ! -L "$runtime" ] || {
    echo "reason=runtime_directory_is_symlink" >&2
    return 1
  }
  mkdir -p "$runtime"
  log_parent="${dns_observation_log%/*}"
  [ -d "$log_parent" ] && [ ! -L "$log_parent" ] || {
    echo "reason=dns_observation_log_parent_invalid" >&2
    return 1
  }
  [ ! -L "$dns_observation_log" ] || {
    echo "reason=dns_observation_log_is_symlink" >&2
    return 1
  }
  if [ -e "$dns_observation_log" ]; then
    [ -f "$dns_observation_log" ] || {
      echo "reason=dns_observation_log_not_regular" >&2
      return 1
    }
  else
    : > "$dns_observation_log"
  fi
  dnsmasq_group="$(id -g dnsmasq 2>/dev/null || true)"
  if [ -n "$dnsmasq_group" ]; then
    chown "0:$dnsmasq_group" "$dns_observation_log"
    if [ "$log_parent" = "$runtime" ]; then
      chown "0:$dnsmasq_group" "$runtime"
      chmod 710 "$runtime"
    fi
    chmod 620 "$dns_observation_log"
  else
    chmod 700 "$runtime"
    chmod 600 "$dns_observation_log"
  fi
}

restart_dnsmasq() {
  ensure_dns_observation_log
  "$dnsmasq_init" restart
  wait_dnsmasq_ready
}

verify_dnsmasq_include_target() {
  configured_confdir="$("$uci_bin" -q get 'dhcp.@dnsmasq[0].confdir' 2>/dev/null || true)"
  active_confdir="${active_dnsmasq%/*}"
  [ -n "$configured_confdir" ] || {
    echo "reason=dnsmasq_confdir_unknown" >&2
    return 1
  }
  [ "$configured_confdir" = "$active_confdir" ] || {
    echo "reason=dnsmasq_include_not_loaded configured_confdir=$configured_confdir active_confdir=$active_confdir" >&2
    return 1
  }
}

start_managed_service() {
  service_init="$1"
  service_name="$2"
  [ -x "$service_init" ] || {
    echo "reason=${service_name}_init_missing" >&2
    return 1
  }
  "$service_init" restart
  "$service_init" running >/dev/null 2>&1 || {
    echo "reason=${service_name}_not_running" >&2
    return 1
  }
}

stop_managed_service() {
  service_init="$1"
  [ -x "$service_init" ] || return 0
  if "$service_init" running >/dev/null 2>&1; then
    "$service_init" stop >/dev/null 2>&1 || {
      echo "reason=managed_service_stop_failed" >&2
      return 1
    }
  fi
}

apply_candidate() {
  take_lock
  verify_token
  pending_matches || exit 3
  [ -f "$txdir/snapshot/manifest.txt" ] && [ -f "$txdir/snapshot/manifest.sha256" ] || {
    echo "reason=snapshot_missing" >&2
    exit 3
  }
  "$router_policy_bin" internal-verify-candidate --candidate "$candidate" --candidate-hash "$candidate_hash" >/dev/null
  "$router_policy_bin" internal-verify-artifacts --root "$generated" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --manifest-hash "$artifact_manifest_hash" >/dev/null
  plan_status="$("$router_policy_bin" internal-validate-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash")"
  plan_xray_enabled="$(printf '%s\n' "$plan_status" | sed -n 's/^xray_enabled=//p' | head -n 1)"
  plan_xray_managed="$(printf '%s\n' "$plan_status" | sed -n 's/^xray_managed=//p' | head -n 1)"
  plan_zapret_enabled="$(printf '%s\n' "$plan_status" | sed -n 's/^zapret_enabled=//p' | head -n 1)"
  plan_zapret_managed="$(printf '%s\n' "$plan_status" | sed -n 's/^zapret_managed=//p' | head -n 1)"
  [ "$plan_xray_enabled" = "$plan_xray_managed" ] && [ "$plan_zapret_enabled" = "$plan_zapret_managed" ] || {
    echo "reason=unmanaged_service_apply_refused" >&2
    exit 3
  }
  arm_transition_guard
  start_timer
  atomic_install "$generated/router-policy.nft" "$active_nft"
  atomic_install "$generated/router-policy-dnsmasq.conf" "$active_dnsmasq"
  atomic_install "$generated/xray.json" "$active_xray"
  if [ "$plan_zapret_enabled" = "true" ]; then
    atomic_install "$generated/nfqws.conf" "$active_zapret"
  else
    rm -f "$active_zapret"
  fi
  install_profile_artifacts "$generated/zapret-profiles.manifest"
  if [ "$plan_xray_enabled" = "true" ]; then
    start_managed_service "$xray_init" "xray"
  else
    stop_managed_service "$xray_init"
  fi
  if [ "$plan_zapret_enabled" = "true" ]; then
    start_managed_service "$zapret_init" "zapret"
  else
    stop_managed_service "$zapret_init"
  fi
  start_profile_services "$active_zapret_profiles"
  ROUTER_POLICY_IP_BIN="$ip_bin" ROUTER_POLICY_UCI_BIN="$uci_bin" "$router_policy_bin" internal-apply-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash"
  reload_project_firewall
  restart_dnsmasq
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "candidate_hash=$candidate_hash"
    echo "artifact_manifest_hash=$artifact_manifest_hash"
    echo "transaction_state=applied"
    echo "updated_at=$(now_utc)"
  } > "$active_file.tmp"
  mv "$active_file.tmp" "$active_file"
  write_status "applied"
  echo "applied=true"
  echo "active_transaction=$txid"
  echo "active_revision=$revision"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

active_matches() {
  [ -f "$active_file" ] || return 1
  active_tx="$(sed -n 's/^transaction_id=//p' "$active_file" | head -n 1)"
  active_revision="$(sed -n 's/^revision_id=//p' "$active_file" | head -n 1)"
  active_candidate_hash="$(sed -n 's/^candidate_hash=//p' "$active_file" | head -n 1)"
  active_artifact_manifest_hash="$(sed -n 's/^artifact_manifest_hash=//p' "$active_file" | head -n 1)"
  [ "$active_tx" = "$txid" ] && [ "$active_revision" = "$revision" ] && [ "$active_candidate_hash" = "$candidate_hash" ] && [ "$active_artifact_manifest_hash" = "$artifact_manifest_hash" ]
}

verify_management() {
  verify_token
  active_matches || exit 4
  process_health=false
  loopback_api_health=false
  loopback_api_required=true
  proof_valid=false
  lan_management_path=false
  admin_http_path=false
  admin_http_required=false
  route_to_management_client=false
  default_gateway_path=false
  dns_availability=false
  legacy_management_env_present=false
  management_mode=unknown
  management_interface=unknown
  management_subnet=unknown
  admin_http_url=""
  admin_http_health=false
  proof_error=""
  if "$pidof_bin" router-policy >/dev/null 2>&1; then process_health=true; fi
  if "$wget_bin" -q -T 3 -O - http://127.0.0.1:8787/api/v1/health >/dev/null 2>&1; then loopback_api_health=true; fi
  [ ! -f "$state/diagnostics/management.env" ] || legacy_management_env_present=true
  proof_error_file="$runtime/management-proof-$revision-$txid.error"
  if proof_output="$(ROUTER_POLICY_CONFIG="$candidate" "$router_policy_bin" internal-verify-management-proof --transaction "$txid" --revision "$revision" 2>"$proof_error_file")"; then
    proof_valid=true
    management_mode="$(printf '%s\n' "$proof_output" | sed -n 's/^management_mode=//p' | head -n 1)"
    management_interface="$(printf '%s\n' "$proof_output" | sed -n 's/^management_interface=//p' | head -n 1)"
    management_subnet="$(printf '%s\n' "$proof_output" | sed -n 's/^management_subnet=//p' | head -n 1)"
    management_client_ip="$(printf '%s\n' "$proof_output" | sed -n 's/^management_client_ip=//p' | head -n 1)"
    control_plane_url="$(printf '%s\n' "$proof_output" | sed -n 's/^control_plane_url=//p' | head -n 1)"
    admin_http_url="$(printf '%s\n' "$proof_output" | sed -n 's/^admin_http_url=//p' | head -n 1)"
    admin_http_required="$(printf '%s\n' "$proof_output" | sed -n 's/^admin_http_required=//p' | head -n 1)"
    admin_http_health="$(printf '%s\n' "$proof_output" | sed -n 's/^admin_http_health=//p' | head -n 1)"
    # LAN/automatic proofs validate the controller through the proved
    # management interface. Requiring a second loopback listener would reject
    # the supported LAN-bound listener even when that signed path is healthy.
    # Headless proofs retain the stricter local check because their control
    # plane URL is loopback.
    case "$management_mode" in
      lan|automatic) loopback_api_required=false ;;
    esac
    if "$ip_bin" route get "$management_client_ip" 2>/dev/null | grep -F "dev $management_interface" >/dev/null 2>&1; then
      route_to_management_client=true
    fi
    if "$wget_bin" -q -T 3 -O - "$control_plane_url" >/dev/null 2>&1 && [ "$route_to_management_client" = "true" ]; then
      lan_management_path=true
    fi
    if [ "$admin_http_required" = "false" ] || [ "$admin_http_health" = "true" ]; then
      admin_http_path=true
    fi
    rm -f "$proof_error_file"
  else
    proof_error="$(head -c 256 "$proof_error_file" 2>/dev/null | tr '\r\n' '  ' | sed 's/[^A-Za-z0-9_.: =\/-]/_/g')"
    rm -f "$proof_error_file"
  fi
  if "$ip_bin" route show default 2>/dev/null | grep -q '^default'; then default_gateway_path=true; fi
  if "$nslookup_bin" localhost 127.0.0.1 >/dev/null 2>&1; then dns_availability=true; fi
  echo "process_health=$process_health"
  echo "loopback_api_health=$loopback_api_health"
  echo "loopback_api_required=$loopback_api_required"
  echo "proof_valid=$proof_valid"
  echo "management_mode=$management_mode"
  echo "management_interface=$management_interface"
  echo "management_subnet=$management_subnet"
  echo "route_to_management_client=$route_to_management_client"
  echo "lan_management_path=$lan_management_path"
  echo "admin_http_required=$admin_http_required"
  echo "admin_http_health=$admin_http_health"
  echo "admin_http_url=$admin_http_url"
  echo "admin_http_path=$admin_http_path"
  echo "legacy_management_env_present=$legacy_management_env_present"
  echo "default_gateway_path=$default_gateway_path"
  echo "dns_availability=$dns_availability"
  if [ "$process_health" != "true" ] || { [ "$loopback_api_required" = "true" ] && [ "$loopback_api_health" != "true" ]; }; then
    write_status "management_failed"
    echo "management_ok=false"
    echo "verification_status=ERROR"
    exit 4
  fi
  if [ "$proof_valid" != "true" ]; then
    write_status "management_unverified"
    echo "management_ok=false"
    echo "verification_status=UNVERIFIED"
    echo "reason=management_proof_missing_or_invalid"
    [ -z "${proof_error:-}" ] || echo "proof_error=$proof_error"
    return 0
  fi
  if [ "$lan_management_path" = "true" ] && [ "$admin_http_path" = "true" ]; then
    write_status "management_verified"
    echo "management_ok=true"
    echo "verification_status=OK"
  else
    write_status "management_failed"
    echo "management_ok=false"
    echo "verification_status=ERROR"
    echo "reason=management_path_lost_after_apply"
    exit 4
  fi
}

verify_data_plane() {
  verify_token
  active_matches || exit 5
  evidence_file="$txdir/data-plane-evidence.json"
	flow_plan_status="$("$router_policy_bin" internal-validate-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash")"
	flow_required="$(printf '%s\n' "$flow_plan_status" | sed -n 's/^flow_offloading_required=//p' | head -n 1)"
	flow_status="$(printf '%s\n' "$flow_plan_status" | sed -n 's/^flow_offloading_status=//p' | head -n 1)"
	if [ "$flow_required" = "true" ] && { [ "$flow_status" = "DISABLE_PLANNED" ] || [ "$flow_status" = "VERIFIED_DISABLED" ]; }; then
		flow_value="$("$uci_bin" -q get "$flow_offload_uci_key" 2>/dev/null || true)"
		flow_hw_value="$("$uci_bin" -q get "$flow_offload_hw_uci_key" 2>/dev/null || true)"
		if [ "$flow_value" != "0" ] || [ "$flow_hw_value" != "0" ]; then
			write_status "data_plane_failed"
			echo "data_plane_ok=false"
			echo "verification_status=ERROR"
			echo "reason=flow_offloading_not_disabled"
			exit 5
		fi
	fi
  if [ ! -f "$evidence_file" ]; then
		if [ "${ROUTER_POLICY_AUTO_COLLECT_EVIDENCE:-1}" = "1" ]; then
			collection_error_file="$txdir/data-plane-collection.error"
			if ! ROUTER_POLICY_CONFIG="$candidate" "$router_policy_bin" internal-collect-data-plane-evidence --plan "$generated/verification-plan.json" --out "$evidence_file" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --manifest-hash "$artifact_manifest_hash" >/dev/null 2>"$collection_error_file"; then
				collection_error="$(head -c 512 "$collection_error_file" | tr '\r\n' '  ' | sed 's/[^A-Za-z0-9_.: =\/-]/_/g')"
				write_status "data_plane_unverified"
				echo "data_plane_ok=false"
				echo "verification_status=UNVERIFIED"
				echo "reason=data_plane_evidence_collection_failed"
				echo "collection_error=$collection_error"
				return 0
			fi
			rm -f "$collection_error_file"
		else
			write_status "data_plane_unverified"
			echo "data_plane_ok=false"
			echo "verification_status=UNVERIFIED"
			echo "reason=data_plane_evidence_missing"
			return 0
		fi
  fi
  if "$router_policy_bin" internal-verify-data-plane --plan "$generated/verification-plan.json" --evidence "$evidence_file" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --manifest-hash "$artifact_manifest_hash" >/dev/null; then
    write_status "data_plane_verified"
    echo "data_plane_ok=true"
    echo "verification_status=OK"
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "candidate_hash=$candidate_hash"
    echo "artifact_manifest_hash=$artifact_manifest_hash"
  else
    write_status "data_plane_failed"
    echo "data_plane_ok=false"
    echo "verification_status=ERROR"
    exit 5
  fi
}

emit_commit_binding() {
  commit_state="$1"
  commit_value="$2"
  rollback_value="$3"
  if [ -z "${candidate_hash:-}" ] && [ -f "$binding_file" ]; then
    candidate_hash="$(sed -n 's/^candidate_hash=//p' "$binding_file" | head -n 1)"
  fi
  if [ -z "${artifact_manifest_hash:-}" ] && [ -f "$binding_file" ]; then
    artifact_manifest_hash="$(sed -n 's/^artifact_manifest_hash=//p' "$binding_file" | head -n 1)"
  fi
  [ -n "${candidate_hash:-}" ] && [ -n "${artifact_manifest_hash:-}" ] || {
    echo "reason=commit_binding_hashes_missing" >&2
    return 1
  }
  echo "protocol_version=1"
  echo "operation=$4"
  echo "request_id=${txid}-${revision}"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
  echo "transaction_state=$commit_state"
  echo "committed=$commit_value"
  echo "rollback_capable=$rollback_value"
  echo "generation=$revision"
}

write_active_transaction_state() {
  state_value="$1"
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "candidate_hash=$candidate_hash"
    echo "artifact_manifest_hash=$artifact_manifest_hash"
    echo "transaction_state=$state_value"
    echo "updated_at=$(now_utc)"
  } > "$active_file.tmp"
  mv "$active_file.tmp" "$active_file"
}

commit_prepared_tx() {
  current_status="$(sed -n 's/^status=//p' "$txdir/status.env" 2>/dev/null | head -n 1)"
  case "$current_status" in
    committed)
      emit_commit_binding committed true false commit-prepared
      echo "already_committed=true"
      return 0
      ;;
    adapter_activated|control_plane_committed)
      emit_commit_binding adapter_activated false true commit-prepared
      echo "already_prepared=true"
      return 0
      ;;
  esac
  take_lock
  verify_token
  active_matches || {
    echo "reason=active_transaction_mismatch" >&2
    exit 6
  }
  write_active_transaction_state "adapter_activated"
  write_status "adapter_activated"
  emit_commit_binding adapter_activated false true commit-prepared
}

finalize_commit_tx() {
  current_status="$(sed -n 's/^status=//p' "$txdir/status.env" 2>/dev/null | head -n 1)"
  if [ "$current_status" = "committed" ]; then
    emit_commit_binding committed true false finalize-commit
    echo "already_committed=true"
    return 0
  fi
  case "$current_status" in
    adapter_activated|control_plane_committed) ;;
    *)
      echo "reason=commit_prepared_required" >&2
      exit 6
      ;;
  esac
  take_lock
  verify_token
  active_matches || {
    echo "reason=active_transaction_mismatch" >&2
    exit 6
  }
  # The adapter is only finalized after the control plane has persisted its
  # active revision.  The caller marks control_plane_committed before invoking
  # this command; this shell step never removes rollback capability early.
  write_active_transaction_state "committed"
  create_snapshot "$state/last-good" "$active_file" "$generated" "$candidate"
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "candidate_hash=$candidate_hash"
    echo "artifact_manifest_hash=$artifact_manifest_hash"
    echo "committed_at=$(now_utc)"
  } > "$state/last-good/transaction.env.tmp"
  mv "$state/last-good/transaction.env.tmp" "$state/last-good/transaction.env"
  printf '%s\n' "$revision" > "$state/active-revision.tmp"
  mv "$state/active-revision.tmp" "$state/active-revision"
  rm -f "$pending_file"
  cancel_timer
  write_status "committed"
  rm -f "$capability_file"
  emit_commit_binding committed true false finalize-commit
}

commit_tx() {
  commit_prepared_tx
  finalize_commit_tx
}

known_restore_target() {
  restore_target="$1"
  restore_owner="$2"
  case "$restore_owner:$restore_target" in
    "project:$config"|"project:$active_nft"|"project:$active_dnsmasq"|"project:$active_xray"|"project:$active_zapret"|"project:$active_zapret_profiles"|"project:$active_file") return 0 ;;
    "project-service:service:$xray_init"|"project-service:service:$zapret_init") return 0 ;;
    "openwrt-uci:uci:$flow_offload_uci_key"|"openwrt-uci:uci:$flow_offload_hw_uci_key") return 0 ;;
    *) return 1 ;;
  esac
}

profile_restore_target_allowed() {
  restore_target="$1"
  restore_owner="$2"
  case "$restore_owner" in
    project)
      case "$restore_target" in
        "$zapret_profile_dir/"*.conf)
          profile_id="${restore_target#"$zapret_profile_dir/"}"
          profile_id="${profile_id%.conf}"
          profile_id_valid "$profile_id"
          ;;
        *) return 1 ;;
      esac
      ;;
    project-service)
      case "$restore_target" in
        service:"$zapret_profile_init_prefix"*)
          profile_id="${restore_target#"service:$zapret_profile_init_prefix"}"
          profile_id_valid "$profile_id"
          ;;
        *) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

verify_snapshot() {
  snapshot_dir="$1"
  [ -f "$snapshot_dir/manifest.txt" ] && [ -f "$snapshot_dir/manifest.sha256" ] || return 1
  expected_manifest="$(cat "$snapshot_dir/manifest.sha256")"
  actual_manifest="$(sha_file "$snapshot_dir/manifest.txt")"
  [ "$expected_manifest" = "$actual_manifest" ] || return 1
  while IFS='|' read -r restore_target restore_state restore_name restore_bytes restore_hash restore_owner; do
    known_restore_target "$restore_target" "$restore_owner" || profile_restore_target_allowed "$restore_target" "$restore_owner" || return 1
    case "$restore_state" in
      present)
        [ -f "$snapshot_dir/$restore_name" ] || return 1
        actual_bytes="$(wc -c < "$snapshot_dir/$restore_name" | tr -d ' ')"
        actual_hash="sha256:$(sha_file "$snapshot_dir/$restore_name")"
        [ "$actual_bytes" = "$restore_bytes" ] && [ "$actual_hash" = "$restore_hash" ] || return 1
        ;;
      absent)
        [ -f "$snapshot_dir/$restore_name.absent" ] || return 1
        [ "$(cat "$snapshot_dir/$restore_name.absent")" = "$restore_target" ] || return 1
        ;;
      *) return 1 ;;
    esac
  done < "$snapshot_dir/manifest.txt"
}

restore_snapshot() {
  snapshot_dir="$1"
  restore_bootstrap="${2:-true}"
  stop_profile_services "$active_zapret_profiles" || return 1
  verify_snapshot "$snapshot_dir" || {
    echo "reason=snapshot_integrity_failed" >&2
    return 1
  }
  uci_restore_needed=false
  while IFS='|' read -r restore_target restore_state restore_name _restore_bytes _restore_hash restore_owner; do
    known_restore_target "$restore_target" "$restore_owner" || profile_restore_target_allowed "$restore_target" "$restore_owner" || return 1
    if [ "$restore_owner" = "project-service" ]; then
      [ "$restore_state" = "present" ] || return 1
      restore_value="$(cat "$snapshot_dir/$restore_name")"
      case "$restore_value" in running|stopped) ;; *) return 1 ;; esac
      continue
    fi
    if [ "$restore_owner" = "project" ]; then
      if [ "$restore_bootstrap" != "true" ] && [ "$restore_target" = "$config" ]; then
        continue
      fi
      if [ "$restore_state" = "present" ]; then
        atomic_install "$snapshot_dir/$restore_name" "$restore_target"
      elif [ "$restore_state" = "absent" ]; then
        rm -f "$restore_target"
      else
        return 1
      fi
      continue
    fi
    restore_key="${restore_target#uci:}"
    if [ "$restore_state" = "present" ]; then
      restore_value="$(cat "$snapshot_dir/$restore_name")"
      case "$restore_value" in 0|1) ;; *) return 1 ;; esac
      "$uci_bin" set "$restore_key=$restore_value"
    elif [ "$restore_state" = "absent" ]; then
      # Missing is the expected idempotent state; a failed delete of an
      # existing option must abort recovery instead of being hidden.
      if "$uci_bin" -q get "$restore_key" >/dev/null 2>&1; then
        "$uci_bin" delete "$restore_key" >/dev/null 2>&1 || return 1
      fi
    else
      return 1
    fi
    uci_restore_needed=true
  done < "$snapshot_dir/manifest.txt"
  if [ "${uci_restore_needed:-false}" = "true" ]; then
    "$uci_bin" commit firewall
  fi
}

restore_service_state() {
  snapshot_dir="$1"
  state_name="$2"
  service_init="$3"
  service_name="$4"
  if [ ! -f "$snapshot_dir/$state_name" ]; then
    # Snapshots created before manifest v6 did not own these project services.
    stop_managed_service "$service_init"
    return 0
  fi
  desired="$(cat "$snapshot_dir/$state_name")"
  if [ "$desired" = "running" ]; then
    start_managed_service "$service_init" "$service_name"
  else
    stop_managed_service "$service_init"
  fi
}

restore_profile_service_states() {
  snapshot_dir="$1"
  [ -f "$snapshot_dir/manifest.txt" ] || return 1
  while IFS='|' read -r restore_target restore_state restore_name restore_bytes restore_hash restore_owner; do
    [ "$restore_owner" = "project-service" ] || continue
    case "$restore_target" in
      service:"$zapret_profile_init_prefix"*)
        profile_init="${restore_target#service:}"
        profile_name="${profile_init##*/}"
        restore_service_state "$snapshot_dir" "$restore_name" "$profile_init" "$profile_name"
        ;;
    esac
  done < "$snapshot_dir/manifest.txt"
}

service_state_matches() {
  state_name="$1"
  service_init="$2"
  [ -f "$state/last-good/$state_name" ] || return 1
  desired_state="$(cat "$state/last-good/$state_name")"
  current_state=stopped
  "$service_init" running >/dev/null 2>&1 && current_state=running
  [ "$current_state" = "$desired_state" ]
}

uci_state_matches() {
  state_name="$1"
  uci_key="$2"
  if [ -f "$state/last-good/$state_name" ]; then
    desired_uci="$(cat "$state/last-good/$state_name")"
    current_uci="$("$uci_bin" -q get "$uci_key" 2>/dev/null)" || return 1
    [ "$current_uci" = "$desired_uci" ]
    return
  fi
  [ -f "$state/last-good/$state_name.absent" ] || return 1
  ! "$uci_bin" -q get "$uci_key" >/dev/null 2>&1
}

recovery_active_matches() {
  [ -f "$active_file" ] || return 1
  [ "$(sed -n 's/^transaction_id=//p' "$active_file" | head -n 1)" = "$txid" ] &&
    [ "$(sed -n 's/^revision_id=//p' "$active_file" | head -n 1)" = "$revision" ] &&
    [ "$(sed -n 's/^candidate_hash=//p' "$active_file" | head -n 1)" = "$recovery_candidate_hash" ] &&
    [ "$(sed -n 's/^artifact_manifest_hash=//p' "$active_file" | head -n 1)" = "$recovery_artifact_manifest_hash" ] &&
    [ "$(sed -n 's/^transaction_state=//p' "$active_file" | head -n 1)" = "committed" ]
}

profile_deployment_matches() {
  recovery_generated="$1"
  if [ ! -f "$recovery_generated/zapret-profiles.manifest" ]; then
    [ ! -e "$active_zapret_profiles" ] || return 1
    return 0
  fi
  [ -f "$active_zapret_profiles" ] || return 1
  cmp -s "$recovery_generated/zapret-profiles.manifest" "$active_zapret_profiles" || return 1
  profile_manifest_validate "$recovery_generated/zapret-profiles.manifest" || return 1
  while IFS='|' read -r profile_id profile_config profile_init profile_queue profile_extra; do
    [ -z "${profile_id:-}" ] && continue
    cmp -s "$(profile_artifact_config "$recovery_generated" "$profile_id")" "$profile_config" || return 1
    cmp -s "$(profile_artifact_service "$recovery_generated" "$profile_id")" "$profile_init" || return 1
    service_state_matches "profile-$profile_id.service.state" "$profile_init" || return 1
  done < "$recovery_generated/zapret-profiles.manifest"
}

committed_deployment_matches() {
  recovery_generated="$1"
  recovery_active_matches || return 1
  [ ! -f "$boot_guard_file" ] || return 1
  "$router_policy_bin" internal-verify-candidate --candidate "$state/last-good/router-policy-config.json" --candidate-hash "$recovery_candidate_hash" >/dev/null || return 1
  cmp -s "$recovery_generated/router-policy.nft" "$active_nft" || return 1
  cmp -s "$recovery_generated/router-policy-dnsmasq.conf" "$active_dnsmasq" || return 1
  cmp -s "$recovery_generated/xray.json" "$active_xray" || return 1
  plan_status="$("$router_policy_bin" internal-validate-ip-plan --plan "$recovery_generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$recovery_candidate_hash")" || return 1
  plan_zapret_enabled="$(printf '%s\n' "$plan_status" | sed -n 's/^zapret_enabled=//p' | head -n 1)"
  if [ "$plan_zapret_enabled" = "true" ]; then
    cmp -s "$recovery_generated/nfqws.conf" "$active_zapret" || return 1
  else
    [ ! -e "$active_zapret" ] || return 1
  fi
  profile_deployment_matches "$recovery_generated" || return 1
  service_state_matches "xray-service.state" "$xray_init" || return 1
  service_state_matches "zapret-service.state" "$zapret_init" || return 1
  "$dnsmasq_init" running >/dev/null 2>&1 || return 1
  uci_state_matches "flow-offloading.uci" "$flow_offload_uci_key" || return 1
  uci_state_matches "flow-offloading-hw.uci" "$flow_offload_hw_uci_key" || return 1
  "$nft_bin" list table inet router_policy >/dev/null 2>&1 || return 1
  ROUTER_POLICY_IP_BIN="$ip_bin" "$router_policy_bin" internal-verify-applied-ip-plan --plan "$recovery_generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$recovery_candidate_hash" >/dev/null || return 1
}

reload_restored_state() {
  snapshot_dir="$1"
  reload_project_firewall
  restart_dnsmasq
  restore_service_state "$snapshot_dir" "xray-service.state" "$xray_init" "xray"
  restore_service_state "$snapshot_dir" "zapret-service.state" "$zapret_init" "zapret"
  restore_profile_service_states "$snapshot_dir"
}

rollback_tx() {
  current_status="$(sed -n 's/^status=//p' "$txdir/status.env" 2>/dev/null | head -n 1)"
  if [ "$current_status" = "rolled_back" ]; then
    echo "rollback=true"
    echo "already_rolled_back=true"
    return 0
  fi
  if [ "$current_status" = "committed" ]; then
    emit_commit_binding committed true false rollback
    echo "rollback=false"
    echo "stale_timer_ignored=true"
    echo "reason=transaction_already_committed"
    return 0
  fi
  if [ "$current_status" = "control_plane_committed" ]; then
    emit_commit_binding control_plane_committed false true rollback
    echo "rollback=false"
    echo "reason=control_plane_commit_requires_finalize"
    return 0
  fi
  verify_token
  case "$current_status" in
    applied|management_failed|management_unverified|management_verified|data_plane_unverified|data_plane_failed|data_plane_verified)
      if [ -f "$active_file" ] && ! active_matches; then
        if ! cancel_timer; then
          echo "rollback=false"
          echo "reason=timer_cancellation_failed" >&2
          exit 3
        fi
        echo "rollback=false"
        echo "stale_timer_ignored=true"
        echo "reason=active_revision_changed"
        return 0
      fi
      ;;
  esac
  take_lock
  verify_token
  if ! cancel_timer; then
    echo "rollback=false"
    echo "reason=timer_cancellation_failed" >&2
    exit 3
  fi
  if [ -f "$txdir/snapshot/manifest.txt" ]; then
    restore_snapshot "$txdir/snapshot"
    reload_restored_state "$txdir/snapshot"
    echo "snapshot_restored=true"
    if [ -f "$txdir/snapshot/ip-state.json" ] && [ -f "$generated/ip-plan.json" ]; then
      if ! ROUTER_POLICY_IP_BIN="$ip_bin" "$router_policy_bin" internal-rollback-ip-state --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash" --pre-state "$txdir/snapshot/ip-state.json" >/dev/null 2>&1; then
        echo "reason=ip_state_rollback_failed" >&2
        exit 3
      fi
      echo "ip_state_rolled_back=true"
    fi
  else
    echo "snapshot_restored=false"
    echo "reason=no_snapshot_no_data_plane_change"
  fi
  if pending_matches; then rm -f "$pending_file"; fi
  if active_matches; then rm -f "$active_file"; fi
  # A successful owned restore is the only safe rollback point.  If any
  # restore step failed, set -e leaves the fence armed for recovery.
  clear_boot_guard
  write_status "rolled_back"
  echo "protocol_version=1"
  echo "operation=rollback"
  echo "rollback=true"
  echo "committed=false"
  echo "rollback_capable=false"
  echo "transaction_state=rolled_back"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=$candidate_hash"
  echo "artifact_manifest_hash=$artifact_manifest_hash"
}

reconcile_tx() {
  [ -f "$state/last-good/manifest.txt" ] || {
    echo "protocol_version=1"
    echo "operation=reconcile"
    echo "reconcile=skipped-no-last-good"
    echo "transaction_state=skipped"
    return 0
  }
  load_recovery_args
  require_recovery_args
  take_lock
  recovery_binding="$state/last-good/active-transaction.env"
  [ -f "$recovery_binding" ] || recovery_binding="$state/last-good/transaction.env"
  recovered_tx="$(sed -n 's/^transaction_id=//p' "$recovery_binding" | head -n 1)"
  recovered_revision="$(sed -n 's/^revision_id=//p' "$recovery_binding" | head -n 1)"
  recovered_candidate_hash="$(sed -n 's/^candidate_hash=//p' "$recovery_binding" | head -n 1)"
  recovered_artifact_hash="$(sed -n 's/^artifact_manifest_hash=//p' "$recovery_binding" | head -n 1)"
  [ "$recovered_tx" = "$txid" ] && [ "$recovered_revision" = "$revision" ] && [ "$recovered_candidate_hash" = "$recovery_candidate_hash" ] && [ "$recovered_artifact_hash" = "$recovery_artifact_manifest_hash" ] || {
    echo "reason=recovery_binding_mismatch" >&2
    exit 3
  }
  recovery_generated="$state/last-good/generated"
  if [ ! -d "$recovery_generated" ]; then
    recovery_generated="$txroot/$revision/$txid/generated"
  fi
  [ -d "$recovery_generated" ] || {
    echo "reason=recovery_artifacts_missing" >&2
    exit 3
  }
  "$router_policy_bin" internal-verify-candidate --candidate "$state/last-good/router-policy-config.json" --candidate-hash "$recovery_candidate_hash" >/dev/null
  "$router_policy_bin" internal-verify-artifacts --root "$recovery_generated" --transaction "$txid" --revision "$revision" --candidate-hash "$recovery_candidate_hash" --manifest-hash "$recovery_artifact_manifest_hash" >/dev/null
  "$router_policy_bin" internal-validate-ip-plan --plan "$recovery_generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$recovery_candidate_hash" >/dev/null
  if committed_deployment_matches "$recovery_generated"; then
    # The process may have died after the durable commit and before the normal
    # clear operation.  Only an exact committed-generation match may remove
    # the fail-closed fence.
    clear_boot_guard
    echo "reconcile=noop"
    echo "noop=true"
    echo "network_changed=false"
    echo "protocol_version=1"
    echo "operation=reconcile"
    echo "generation=$revision"
    echo "transaction_id=$txid"
    echo "active_transaction=$txid"
    echo "active_revision=$revision"
    echo "active_candidate_hash=$recovery_candidate_hash"
    echo "active_artifact_manifest_hash=$recovery_artifact_manifest_hash"
    echo "transaction_state=committed"
    return 0
  fi
  install_boot_guard
  restore_snapshot "$state/last-good" false
  restore_service_state "$state/last-good" "xray-service.state" "$xray_init" "xray"
  restore_service_state "$state/last-good" "zapret-service.state" "$zapret_init" "zapret"
  restore_profile_service_states "$state/last-good"
  ROUTER_POLICY_IP_BIN="$ip_bin" ROUTER_POLICY_UCI_BIN="$uci_bin" "$router_policy_bin" internal-apply-ip-plan --plan "$recovery_generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$recovery_candidate_hash" >/dev/null
  reload_project_firewall
  restart_dnsmasq
  clear_boot_guard
  echo "reconcile=ok"
  echo "protocol_version=1"
  echo "operation=reconcile"
  echo "generation=$revision"
  echo "transaction_id=$txid"
  echo "active_transaction=$txid"
  echo "active_revision=$revision"
  echo "active_candidate_hash=$recovery_candidate_hash"
  echo "active_artifact_manifest_hash=$recovery_artifact_manifest_hash"
  echo "transaction_state=committed"
}

status_tx() {
  echo "adapter=router-policy-openwrt"
  echo "state_dir=$state"
  echo "runtime_dir=$runtime"
  if [ -f "$active_file" ]; then
    sed -n 's/^transaction_id=/active_transaction=/p; s/^revision_id=/active_revision=/p; s/^candidate_hash=/active_candidate_hash=/p; s/^artifact_manifest_hash=/active_artifact_manifest_hash=/p; s/^transaction_state=/transaction_state=/p' "$active_file"
    status_value="$(sed -n 's/^status=//p' "$state/transactions/$revision/$txid/status.env" 2>/dev/null | head -n 1)"
  else
    echo "active_transaction="
    echo "active_revision="
    echo "active_candidate_hash="
    echo "active_artifact_manifest_hash="
    echo "transaction_state=idle"
  fi
  echo "protocol_version=1"
}

if [ "${ROUTER_POLICY_ADAPTER_LIB_ONLY:-0}" = "1" ]; then
  return 0
fi

case "$cmd" in
  diagnose)
    [ "$config" = "$known_config" ] || exit 2
    echo "diagnose=ok"
    ;;
  reconcile)
    [ "$config" = "$known_config" ] || exit 2
    reconcile_tx
    ;;
  boot-guard)
    [ "$config" = "$known_config" ] || exit 2
    install_boot_guard
    ;;
  clear-boot-guard)
    [ "$config" = "$known_config" ] || exit 2
    clear_boot_guard
    ;;
  status)
    [ "$config" = "$known_config" ] || exit 2
    status_tx
    ;;
  prepare|validate-candidate|snapshot-current|apply-candidate|verify-management|verify-data-plane|commit|commit-prepared|finalize-commit|rollback|clear-boot-guard-bound|replace-owned-nft|apply-ip-plan|rollback-ip-plan|artifact-install|artifact-remove)
    require_transaction_args
    case "$cmd" in
      prepare) prepare_tx ;;
      validate-candidate) validate_candidate ;;
      snapshot-current) snapshot_current ;;
      apply-candidate) apply_candidate ;;
      verify-management) verify_management ;;
      verify-data-plane) verify_data_plane ;;
      commit) commit_tx ;;
      commit-prepared) commit_prepared_tx ;;
      finalize-commit) finalize_commit_tx ;;
      rollback) rollback_tx ;;
      clear-boot-guard-bound) clear_boot_guard_bound ;;
      replace-owned-nft) replace_owned_nft_command ;;
      apply-ip-plan) apply_ip_plan_command ;;
      rollback-ip-plan) rollback_ip_plan_command ;;
      artifact-install) install_artifact_command ;;
      artifact-remove) remove_artifact_command ;;
    esac
    ;;
  *)
    echo "usage: adapter.sh prepare|validate-candidate|snapshot-current|apply-candidate|verify-management|verify-data-plane|commit|commit-prepared|finalize-commit|rollback|replace-owned-nft|apply-ip-plan|rollback-ip-plan|artifact-install|artifact-remove|reconcile|boot-guard|clear-boot-guard|status CONFIG [TX_ID REVISION [CANDIDATE_HASH ARTIFACT_MANIFEST_HASH [ARTIFACT_KIND]]]" >&2
    exit 2
    ;;
esac
