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
state="${STATE_DIR:-/var/lib/router-policy}"
txroot="$state/transactions"
lock_dir="$runtime/transaction.lock"
pending_file="$runtime/pending-transaction.env"
active_file="$runtime/active-transaction.env"
boot_guard_file="$runtime/boot-guard.nft"
timer_dir="$runtime/rollback-timers"
known_config="${ROUTER_POLICY_CONFIG_PATH:-/etc/router-policy/config/default.json}"
router_policy_bin="${ROUTER_POLICY_BIN:-/usr/bin/router-policy}"
adapter_self="${ROUTER_POLICY_ADAPTER_SELF:-/usr/lib/router-policy/openwrt/adapter.sh}"
nft_bin="${NFT_BIN:-nft}"
fw4_bin="${FW4_BIN:-fw4}"
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
active_dnsmasq="${ACTIVE_DNSMASQ:-/etc/dnsmasq.d/router-policy.conf}"
active_xray="${ACTIVE_XRAY:-/etc/router-policy/xray/active.json}"
active_zapret="${ACTIVE_ZAPRET:-/etc/router-policy/zapret/nfqws.conf}"
flow_offload_uci_key='firewall.@defaults[0].flow_offloading'
flow_offload_hw_uci_key='firewall.@defaults[0].flow_offloading_hw'

mkdir -p "$runtime" "$state/last-good" "$state/backups" "$txroot" "$timer_dir"

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

process_start() {
  pid_value="$1"
  [ -r "/proc/$pid_value/stat" ] || return 1
  awk '{print $22}' "/proc/$pid_value/stat"
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

install_boot_guard() {
  [ -f "$state/last-good/manifest.txt" ] || {
    echo "boot_guard=skipped-no-last-good"
    return 0
  }
  mkdir -p "$runtime"
  cat > "$boot_guard_file.tmp" <<'EOF'
table inet router_policy_boot_guard {
  chain forward {
    type filter hook forward priority -400; policy accept;
    counter drop
  }
}
EOF
  mv "$boot_guard_file.tmp" "$boot_guard_file"
  "$nft_bin" delete table inet router_policy_boot_guard >/dev/null 2>&1 || true
  "$nft_bin" -f "$boot_guard_file"
  echo "boot_guard=armed"
}

clear_boot_guard() {
  "$nft_bin" delete table inet router_policy_boot_guard >/dev/null 2>&1 || true
  rm -f "$boot_guard_file"
  echo "boot_guard=cleared"
}

sha_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

verify_token() {
  [ -f "$binding_file" ] && [ -f "$capability_file" ] && [ ! -L "$capability_file" ] || {
    echo "reason=transaction_metadata_missing" >&2
    return 1
  }
  capability_mode="$(stat -c '%a' "$capability_file")"
  capability_owner="$(stat -c '%u' "$capability_file")"
  tx_owner="$(stat -c '%u' "$txdir")"
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

create_snapshot() {
  create_root="$1"
  committed_active_source="${2:-}"
  recovery_artifact_source="${3:-}"
  rm -rf "$create_root.tmp"
  mkdir -p "$create_root.tmp"
  : > "$create_root.tmp/manifest.txt"
  snapshot_one "$config" "router-policy-config.json" "$create_root.tmp"
  snapshot_one "$active_nft" "router-policy.nft" "$create_root.tmp"
  snapshot_one "$active_dnsmasq" "router-policy-dnsmasq.conf" "$create_root.tmp"
  snapshot_one "$active_xray" "xray-active.json" "$create_root.tmp"
  snapshot_one "$active_zapret" "nfqws.conf" "$create_root.tmp"
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
  rm -rf "$create_root"
  mv "$create_root.tmp" "$create_root"
}

snapshot_current() {
  take_lock
  verify_token
  pending_matches || {
    echo "reason=transaction_not_pending" >&2
    exit 3
  }
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
  "$dnsmasq_bin" --test --conf-file="$generated/router-policy-dnsmasq.conf" >/dev/null
  "$xray_bin" run -test -config "$generated/xray.json" >/dev/null
  ip_plan_status="$("$router_policy_bin" internal-validate-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash")"
  printf '%s\n' "$ip_plan_status"
  plan_ready="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^deployment_ready=//p' | head -n 1)"
  plan_reason="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^reason=//p' | head -n 1)"
  plan_simulation="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^simulation=//p' | head -n 1)"
  plan_xray_enabled="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^xray_enabled=//p' | head -n 1)"
  plan_xray_managed="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^xray_managed=//p' | head -n 1)"
  plan_zapret_enabled="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^zapret_enabled=//p' | head -n 1)"
  plan_zapret_managed="$(printf '%s\n' "$ip_plan_status" | sed -n 's/^zapret_managed=//p' | head -n 1)"
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
  value="$(sed -n 's/.*"rollback_timeout_seconds"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$candidate" 2>/dev/null | head -n 1)"
  [ -n "$value" ] || value=120
  echo "$value"
}

start_timer() {
  seconds="$(rollback_timeout)"
  timer_bootstrap="$timer_file.bootstrap"
  rm -f "$timer_bootstrap" "$timer_bootstrap.tmp"
  (
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
      kill "$timer_pid" 2>/dev/null || true
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
  if [ -n "$timer_sleep_pid" ] && kill -0 "$timer_sleep_pid" 2>/dev/null; then
    current_sleep_start="$(process_start "$timer_sleep_pid" 2>/dev/null || true)"
    if [ -n "$current_sleep_start" ] && [ "$current_sleep_start" = "$timer_sleep_start" ]; then
      kill "$timer_sleep_pid" 2>/dev/null || true
    fi
  fi
  if [ -n "$timer_pid" ] && kill -0 "$timer_pid" 2>/dev/null; then
    current_start="$(process_start "$timer_pid" 2>/dev/null || true)"
    if [ -n "$current_start" ] && [ "$current_start" = "$timer_start" ]; then
      kill "$timer_pid" 2>/dev/null || true
    fi
  fi
  rm -f "$timer_file" "$timer_file.bootstrap" "$timer_file.bootstrap.tmp"
}

atomic_install() {
  install_source="$1"
  install_target="$2"
  install_tmp="$install_target.tmp.$txid"
  cp "$install_source" "$install_tmp"
  mv "$install_tmp" "$install_target"
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

delete_nft_table_from() {
  identity_file="$1"
  identity="$(nft_identity "$identity_file" 2>/dev/null || true)"
  [ -n "$identity" ] || return 0
  identity_family="${identity%% *}"
  identity_table="${identity#* }"
  "$nft_bin" delete table "$identity_family" "$identity_table" >/dev/null 2>&1 || true
}

reload_project_firewall() {
  generated_nft=""
  if [ -n "${generated:-}" ]; then
    generated_nft="$generated/router-policy.nft"
    delete_nft_table_from "$generated_nft"
  fi
  if [ "$active_nft" != "$generated_nft" ]; then
    delete_nft_table_from "$active_nft"
  fi
  "$fw4_bin" reload
  if [ -s "$active_nft" ]; then
    "$nft_bin" -f "$active_nft"
  fi
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
  "$service_init" stop >/dev/null 2>&1 || true
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
  start_timer
  atomic_install "$candidate" "$config"
  atomic_install "$generated/router-policy.nft" "$active_nft"
  atomic_install "$generated/router-policy-dnsmasq.conf" "$active_dnsmasq"
  atomic_install "$generated/xray.json" "$active_xray"
  if [ "$plan_zapret_enabled" = "true" ]; then
    atomic_install "$generated/nfqws.conf" "$active_zapret"
  else
    rm -f "$active_zapret"
  fi
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
  ROUTER_POLICY_IP_BIN="$ip_bin" ROUTER_POLICY_UCI_BIN="$uci_bin" "$router_policy_bin" internal-apply-ip-plan --plan "$generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$candidate_hash"
  reload_project_firewall
  "$dnsmasq_init" restart
  wait_dnsmasq_ready
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
  lan_management_path=false
  glinet_uhttpd_path=false
  default_gateway_path=false
  dns_availability=false
  if "$pidof_bin" router-policy >/dev/null 2>&1; then process_health=true; fi
  if "$wget_bin" -q -T 3 -O - http://127.0.0.1:8787/api/v1/health >/dev/null 2>&1; then loopback_api_health=true; fi
  management_evidence="$state/diagnostics/management.env"
  if [ -f "$management_evidence" ]; then
    [ "$(sed -n 's/^lan_management_path=//p' "$management_evidence" | head -n 1)" = "true" ] && lan_management_path=true
    [ "$(sed -n 's/^glinet_uhttpd_path=//p' "$management_evidence" | head -n 1)" = "true" ] && glinet_uhttpd_path=true
  fi
  if "$ip_bin" route show default 2>/dev/null | grep -q '^default'; then default_gateway_path=true; fi
  if "$nslookup_bin" localhost 127.0.0.1 >/dev/null 2>&1; then dns_availability=true; fi
  echo "process_health=$process_health"
  echo "loopback_api_health=$loopback_api_health"
  echo "lan_management_path=$lan_management_path"
  echo "glinet_uhttpd_path=$glinet_uhttpd_path"
  echo "default_gateway_path=$default_gateway_path"
  echo "dns_availability=$dns_availability"
  if [ "$process_health" != "true" ] || [ "$loopback_api_health" != "true" ]; then
    write_status "management_failed"
    echo "management_ok=false"
    echo "verification_status=ERROR"
    exit 4
  fi
  if [ "$lan_management_path" = "true" ] && [ "$glinet_uhttpd_path" = "true" ] && [ "$default_gateway_path" = "true" ] && [ "$dns_availability" = "true" ]; then
    write_status "management_verified"
    echo "management_ok=true"
    echo "verification_status=OK"
  else
    write_status "management_unverified"
    echo "management_ok=false"
    echo "verification_status=UNVERIFIED"
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
    write_status "data_plane_unverified"
    echo "data_plane_ok=false"
    echo "verification_status=UNVERIFIED"
    echo "reason=data_plane_evidence_missing"
    return 0
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

commit_tx() {
  current_status="$(sed -n 's/^status=//p' "$txdir/status.env" 2>/dev/null | head -n 1)"
  if [ "$current_status" = "committed" ]; then
    echo "committed=true"
    echo "already_committed=true"
    return 0
  fi
  take_lock
  verify_token
  active_matches || {
    echo "reason=active_transaction_mismatch" >&2
    exit 6
  }
  cancel_timer
  committed_active="$txdir/committed-active.env"
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "candidate_hash=$candidate_hash"
    echo "artifact_manifest_hash=$artifact_manifest_hash"
    echo "transaction_state=committed"
    echo "updated_at=$(now_utc)"
  } > "$committed_active.tmp"
  mv "$committed_active.tmp" "$committed_active"
  create_snapshot "$state/last-good" "$committed_active" "$generated"
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
  atomic_install "$committed_active" "$active_file"
  rm -f "$pending_file"
  write_status "committed"
  rm -f "$capability_file"
  echo "committed=true"
  echo "active_transaction=$txid"
  echo "active_revision=$revision"
}

known_restore_target() {
  restore_target="$1"
  restore_owner="$2"
  case "$restore_owner:$restore_target" in
    "project:$config"|"project:$active_nft"|"project:$active_dnsmasq"|"project:$active_xray"|"project:$active_zapret"|"project:$active_file") return 0 ;;
    "project-service:service:$xray_init"|"project-service:service:$zapret_init") return 0 ;;
    "openwrt-uci:uci:$flow_offload_uci_key"|"openwrt-uci:uci:$flow_offload_hw_uci_key") return 0 ;;
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
    known_restore_target "$restore_target" "$restore_owner" || return 1
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
  verify_snapshot "$snapshot_dir" || {
    echo "reason=snapshot_integrity_failed" >&2
    return 1
  }
  uci_restore_needed=false
  while IFS='|' read -r restore_target restore_state restore_name _restore_bytes _restore_hash restore_owner; do
    known_restore_target "$restore_target" "$restore_owner" || return 1
    if [ "$restore_owner" = "project-service" ]; then
      [ "$restore_state" = "present" ] || return 1
      restore_value="$(cat "$snapshot_dir/$restore_name")"
      case "$restore_value" in running|stopped) ;; *) return 1 ;; esac
      continue
    fi
    if [ "$restore_owner" = "project" ]; then
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
      "$uci_bin" -q delete "$restore_key" >/dev/null 2>&1 || true
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

reload_restored_state() {
  snapshot_dir="$1"
  reload_project_firewall
  "$dnsmasq_init" restart
  wait_dnsmasq_ready
  restore_service_state "$snapshot_dir" "xray-service.state" "$xray_init" "xray"
  restore_service_state "$snapshot_dir" "zapret-service.state" "$zapret_init" "zapret"
}

rollback_tx() {
  current_status="$(sed -n 's/^status=//p' "$txdir/status.env" 2>/dev/null | head -n 1)"
  if [ "$current_status" = "rolled_back" ]; then
    echo "rollback=true"
    echo "already_rolled_back=true"
    return 0
  fi
  if [ "$current_status" = "committed" ]; then
    cancel_timer || true
    echo "rollback=false"
    echo "stale_timer_ignored=true"
    echo "reason=transaction_already_committed"
    return 0
  fi
  verify_token
  case "$current_status" in
    applied|management_failed|management_unverified|management_verified|data_plane_unverified|data_plane_failed|data_plane_verified)
      if [ -f "$active_file" ] && ! active_matches; then
        cancel_timer || true
        echo "rollback=false"
        echo "stale_timer_ignored=true"
        echo "reason=active_revision_changed"
        return 0
      fi
      ;;
  esac
  take_lock
  verify_token
  cancel_timer || true
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
  write_status "rolled_back"
  echo "rollback=true"
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
}

reconcile_tx() {
  [ -f "$state/last-good/manifest.txt" ] || {
    echo "reconcile=skipped-no-last-good"
    return 0
  }
  load_recovery_args
  install_boot_guard
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
  restore_snapshot "$state/last-good"
  restore_service_state "$state/last-good" "xray-service.state" "$xray_init" "xray"
  restore_service_state "$state/last-good" "zapret-service.state" "$zapret_init" "zapret"
  ROUTER_POLICY_IP_BIN="$ip_bin" ROUTER_POLICY_UCI_BIN="$uci_bin" "$router_policy_bin" internal-apply-ip-plan --plan "$recovery_generated/ip-plan.json" --transaction "$txid" --revision "$revision" --candidate-hash "$recovery_candidate_hash" >/dev/null
  reload_project_firewall
  "$dnsmasq_init" restart
  wait_dnsmasq_ready
  clear_boot_guard
  echo "reconcile=ok"
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
  else
    echo "active_transaction="
    echo "active_revision="
    echo "active_candidate_hash="
    echo "active_artifact_manifest_hash="
    echo "transaction_state=idle"
  fi
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
  prepare|validate-candidate|snapshot-current|apply-candidate|verify-management|verify-data-plane|commit|rollback)
    require_transaction_args
    case "$cmd" in
      prepare) prepare_tx ;;
      validate-candidate) validate_candidate ;;
      snapshot-current) snapshot_current ;;
      apply-candidate) apply_candidate ;;
      verify-management) verify_management ;;
      verify-data-plane) verify_data_plane ;;
      commit) commit_tx ;;
      rollback) rollback_tx ;;
    esac
    ;;
  *)
    echo "usage: adapter.sh prepare|validate-candidate|snapshot-current|apply-candidate|verify-management|verify-data-plane|commit|rollback|reconcile|boot-guard|clear-boot-guard|status CONFIG [TX_ID REVISION [CANDIDATE_HASH ARTIFACT_MANIFEST_HASH]]" >&2
    exit 2
    ;;
esac
