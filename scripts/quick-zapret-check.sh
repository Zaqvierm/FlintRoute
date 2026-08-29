#!/bin/sh
set -eu
umask 077

# This runner is deliberately separate from calibrate-zapret.sh.  It is a
# bounded, curated dataplane check; it never invokes the upstream blockcheck.
# Every attempt owns one temporary nft table, one NFQUEUE and one process
# group.  A HTTP 200 without an observed queue counter is an infrastructure
# failure, never a passing strategy.

CONFIG="${ROUTER_POLICY_CONFIG:-/etc/router-policy/config/default.json}"
NFQWS_BIN="${NFQWS_BIN:-/usr/bin/nfqws}"
RUNTIME_DIR="${ROUTER_POLICY_RUNTIME_DIR:-/tmp/router-policy}"
CATALOG_OUT="${ZAPRET_CATALOG_OUT:-/etc/router-policy/zapret/catalog.json}"
NFT_BIN="${NFT_BIN:-/usr/sbin/nft}"
CURL_BIN="${CURL_BIN:-/usr/bin/curl}"
SETSID_BIN="${SETSID_BIN:-/usr/bin/setsid}"
SU_BIN="${SU_BIN:-/bin/su}"
IP_BIN="${IP_BIN:-/sbin/ip}"
PROBE_USER="${ZAPRET_QUICK_PROBE_USER:-nobody}"
QUEUE_BASE="${ZAPRET_QUICK_QUEUE_BASE:-30000}"
MANAGED_QUEUE="${ZAPRET_MANAGED_QUEUE:-}"
MAX_ADDRESSES="${ZAPRET_QUICK_MAX_ADDRESSES:-2}"

domain=""
bundle_id=""
network_fingerprint=""
mode=""
run_dir=""
lock_dir=""
lock_acquired=0
run_token=""
table=""
nfq_pid=""
nfq_pgid=""
queue=""
strategy_path=""
attempt_index=0
attempt_count=0
attempts_file=""
catalog_file=""
catalog_tmp=""
path_verified_count=0
probe_mode=""
probe_user=""
watchdog_pid=""
route_evidence_value=""

usage() {
  echo "usage: quick-zapret-check.sh --apply --mode quick --domain DOMAIN --bundle-id ID --network-fingerprint sha256:HEX" >&2
}

die() {
  echo "quick Zapret check: $*" >&2
  exit 1
}

require_arg() {
  [ "$#" -ge 2 ] || { usage; exit 2; }
  [ -n "$2" ] || { usage; exit 2; }
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) ;;
    --mode) shift; require_arg --mode "${1:-}"; mode="$1" ;;
    --domain) shift; require_arg --domain "${1:-}"; domain="$1" ;;
    --bundle-id) shift; require_arg --bundle-id "${1:-}"; bundle_id="$1" ;;
    --network-fingerprint) shift; require_arg --network-fingerprint "${1:-}"; network_fingerprint="$1" ;;
    *) usage; exit 2 ;;
  esac
  shift
done

[ "$mode" = "quick" ] || die "only --mode quick is accepted"
case "$domain" in
  ""|.*|-*|*..*|*[!A-Za-z0-9.-]*) die "invalid calibration domain" ;;
esac
[ "${#domain}" -le 253 ] || die "calibration domain is too long"
case "$bundle_id" in
  ""|*[!A-Za-z0-9._-]*) die "invalid calibration bundle ID" ;;
esac
[ "${#bundle_id}" -le 96 ] || die "calibration bundle ID is too long"
case "$network_fingerprint" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) die "network fingerprint must be a sha256 digest" ;;
esac
case "${network_fingerprint#sha256:}" in
  *[!0-9a-fA-F]*) die "network fingerprint must be hexadecimal" ;;
esac

require_absolute_path() {
  case "$1" in
    /*) ;;
    *) die "$2 must be an absolute path" ;;
  esac
}
require_absolute_path "$CONFIG" "runtime config"
require_absolute_path "$NFQWS_BIN" "nfqws binary"
require_absolute_path "$NFT_BIN" "nft binary"
require_absolute_path "$CURL_BIN" "curl binary"
require_absolute_path "$SETSID_BIN" "setsid"
require_absolute_path "$IP_BIN" "ip"
require_absolute_path "$RUNTIME_DIR" "runtime directory"
require_absolute_path "$CATALOG_OUT" "catalog output"
case "$MAX_ADDRESSES" in
  ""|*[!0-9]*) die "quick address limit is invalid" ;;
esac
[ "$MAX_ADDRESSES" -ge 1 ] && [ "$MAX_ADDRESSES" -le 4 ] || die "quick address limit is outside the safe range"

[ "$(id -u)" = "0" ] || die "curated dataplane check requires the managed runtime privilege"
[ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] || die "runtime config is unavailable or symlinked"
require_binary() {
  path="$1"
  label="$2"
  allow_busybox="$3"
  [ -x "$path" ] || die "$label is unavailable"
  [ ! -L "$path" ] && return 0
  resolved=$(readlink -f "$path" 2>/dev/null || true)
  if [ "$allow_busybox" = "yes" ]; then
    case "$resolved" in /bin/busybox|/usr/bin/busybox|/usr/sbin/busybox) return 0 ;; esac
  fi
  die "$label resolves through an untrusted symlink"
}
require_binary "$NFQWS_BIN" "nfqws binary" no
require_binary "$NFT_BIN" "nft binary" no
require_binary "$CURL_BIN" "curl binary" no
require_binary "$SETSID_BIN" "setsid" yes
[ -x "$IP_BIN" ] || die "ip utility is unavailable"

# Most desktop Linux images provide `su`, but the supported embedded OpenWrt
# images often do not.  The runner is already a root-owned, bounded operation;
# when no safe privilege-drop helper exists we keep the path proof by matching
# the output rule to UID 0 and record that fact in every attempt.  We never
# silently fall back when a configured helper exists but is invalid: that is a
# deployment error, not a reason to weaken the contract.
if [ -x "$SU_BIN" ]; then
  require_binary "$SU_BIN" "su" yes
  id "$PROBE_USER" >/dev/null 2>&1 || die "dedicated probe user is unavailable: $PROBE_USER"
  [ "$(id -u "$PROBE_USER")" != "0" ] || die "dedicated probe user must not be root"
  probe_mode="unprivileged"
  probe_user=$(id -u "$PROBE_USER")
else
  [ "$SU_BIN" = "/bin/su" ] || die "su is unavailable"
  [ "$(id -u)" = "0" ] || die "no privilege-drop helper is available; curated dataplane check must run as root"
  probe_mode="root_fallback"
  probe_user=0
fi

mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
lock_dir="$RUNTIME_DIR/zapret-calibration.lock"
mkdir "$lock_dir" 2>/dev/null || die "another Zapret calibration is active"
lock_acquired=1
run_token="q$(printf '%s' "$$-$domain" | sha256sum | awk '{print substr($1,1,12)}')"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if command -v cleanup_attempt >/dev/null 2>&1; then
    cleanup_attempt || status=1
  fi
  if [ -f "$run_dir/routes.before" ] && command -v verify_network_baseline >/dev/null 2>&1; then
    verify_network_baseline || status=1
  fi
  if [ -n "$catalog_tmp" ]; then
    rm -f "$catalog_tmp"
  fi
  [ -n "$run_dir" ] && rm -rf "$run_dir"
  if [ "$lock_acquired" = "1" ]; then
    rmdir "$lock_dir" 2>/dev/null || status=1
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

run_dir="$RUNTIME_DIR/zapret-quick.$run_token"
mkdir "$run_dir"
chmod 700 "$run_dir"
attempts_file="$run_dir/attempts.jsonl"
catalog_file="$run_dir/catalog.json"
catalog_tmp="$run_dir/catalog.tmp"
: > "$attempts_file"

now_ms() {
  value=$(date +%s%3N 2>/dev/null || true)
  case "$value" in
    ''|*[!0-9]*) value=$(date +%s 2>/dev/null || true); case "$value" in ''|*[!0-9]*) return 1 ;; esac; printf '%s000\n' "$value" ;;
    *) printf '%s\n' "$value" ;;
  esac
}

shell_quote() {
  escaped=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
  printf "'%s'" "$escaped"
}

proc_pgid() {
  pid="$1"
  [ -r "/proc/$pid/stat" ] || return 1
  # BusyBox ps does not provide the GNU `ps -o pgid= -p PID` interface.
  # /proc/PID/stat is available on the OpenWrt targets and keeps the lookup
  # independent of the ps implementation.  The closing ')' is located by
  # token, so process names containing spaces do not shift the pgrp field.
  awk '{
    comm_end = 0
    for (i = 2; i <= NF; i++) {
      if ($i ~ /\)$/) {
        comm_end = i
      }
    }
    if (comm_end == 0 || comm_end + 3 > NF) {
      exit 1
    }
    pgid = $(comm_end + 3)
    if (pgid !~ /^[0-9]+$/) {
      exit 1
    }
    print pgid
    found = 1
  }
  END {
    if (!found) {
      exit 1
    }
  }' "/proc/$pid/stat" 2>/dev/null
}

proc_start_time() {
  [ -r "/proc/$1/stat" ] || return 1
  awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}

proc_exe() {
  readlink "/proc/$1/exe" 2>/dev/null
}

proc_cmdline() {
  tr '\000' ' ' < "/proc/$1/cmdline" 2>/dev/null
}

group_exists() {
  pgid="$1"
  case "$pgid" in ""|0|*[!0-9]*) return 1 ;; esac
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    pid=${proc#/proc/}
    [ "$(proc_pgid "$pid")" = "$pgid" ] && return 0
  done
  return 1
}

owned_nfqwss() {
  [ -n "$strategy_path" ] || return 0
  for proc in /proc/[0-9]*; do
    [ -r "$proc/cmdline" ] || continue
    pid=${proc#/proc/}
    [ "$(proc_exe "$pid")" = "$NFQWS_BIN" ] || continue
    command_line=$(proc_cmdline "$pid")
    case "$command_line" in
      *"@$strategy_path"*) printf '%s\n' "$pid" ;;
      *)
        # A daemonized nfqws may rewrite argv or detach into a new session.
        # The per-run environment marker is the second ownership proof; a
        # matching executable alone is never enough to kill a process.
        if [ -r "$proc/environ" ] && tr '\000' '\n' < "$proc/environ" 2>/dev/null | grep -Fqx -- "ROUTER_POLICY_CALIBRATION_RUN_ID=$run_token"; then
          printf '%s\n' "$pid"
        fi
        ;;
    esac
  done
}

cleanup_owned_nfqwss() {
  local_status=0
  for pid in $(owned_nfqwss); do
    kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in $(owned_nfqwss); do
    kill -KILL "$pid" 2>/dev/null || true
  done
  [ -z "$(owned_nfqwss)" ] || local_status=1
  return "$local_status"
}

queue_in_use() {
  needle="queue num $1"
  ruleset=$($NFT_BIN list ruleset 2>/dev/null) || die "unable to inspect nft ruleset before allocating NFQUEUE"
  printf '%s\n' "$ruleset" | grep -Fq "$needle"
}

process_queue_in_use() {
  wanted="--qnum=$1"
  for proc in /proc/[0-9]*; do
    [ -r "$proc/cmdline" ] || continue
    # The needle begins with `--qnum=...`; terminate grep options so BusyBox
    # and GNU grep both treat it as data rather than an unknown long option.
    if proc_cmdline "${proc#/proc/}" | grep -Fq -- "$wanted"; then
      return 0
    fi
  done
  return 1
}

allocate_queue() {
  base="$QUEUE_BASE"
  case "$base" in ""|*[!0-9]*) die "invalid quick NFQUEUE base" ;; esac
  [ "$base" -ge 1024 ] && [ "$base" -le 65520 ] || die "quick NFQUEUE base is outside the safe range"
  offset=0
  while [ "$offset" -lt 16 ]; do
    candidate=$((base + offset))
    if ! queue_in_use "$candidate" && ! process_queue_in_use "$candidate"; then
      queue="$candidate"
      return 0
    fi
    offset=$((offset + 1))
  done
  die "no free NFQUEUE in bounded quick allocation range"
}

write_strategy() {
  profile="$1"
  path="$2"
  strategy_queue="${3:-$queue}"
  case "$profile" in
    general)
      {
        printf '%s\n' "--qnum=$strategy_queue"
        printf '%s\n' "--filter-tcp=80,443"
        printf '%s\n' "--hostlist-domains=$domain"
        printf '%s\n' "--dpi-desync=multisplit"
        printf '%s\n' "--dpi-desync-split-seqovl=568"
        printf '%s\n' "--dpi-desync-split-pos=1"
      } > "$path"
      ;;
    general-alt)
      {
        printf '%s\n' "--qnum=$strategy_queue"
        printf '%s\n' "--filter-tcp=80,443"
        printf '%s\n' "--hostlist-domains=$domain"
        printf '%s\n' "--dpi-desync=fake,fakedsplit"
        printf '%s\n' "--dpi-desync-repeats=6"
        printf '%s\n' "--dpi-desync-fooling=ts"
        printf '%s\n' "--dpi-desync-fakedsplit-pattern=0x00"
      } > "$path"
      ;;
    general-alt2)
      {
        printf '%s\n' "--qnum=$strategy_queue"
        printf '%s\n' "--filter-tcp=80,443"
        printf '%s\n' "--hostlist-domains=$domain"
        printf '%s\n' "--dpi-desync=multisplit"
        printf '%s\n' "--dpi-desync-split-seqovl=652"
        printf '%s\n' "--dpi-desync-split-pos=2"
      } > "$path"
      ;;
    general-alt4)
      {
        printf '%s\n' "--qnum=$strategy_queue"
        printf '%s\n' "--filter-tcp=80,443"
        printf '%s\n' "--hostlist-domains=$domain"
        printf '%s\n' "--dpi-desync=fake,multisplit"
        printf '%s\n' "--dpi-desync-repeats=6"
        printf '%s\n' "--dpi-desync-split-seqovl=664"
        printf '%s\n' "--dpi-desync-split-pos=1"
        printf '%s\n' "--dpi-desync-fooling=ts"
      } > "$path"
      ;;
    general-alt6)
      {
        printf '%s\n' "--qnum=$strategy_queue"
        printf '%s\n' "--filter-tcp=80,443"
        printf '%s\n' "--hostlist-domains=$domain"
        printf '%s\n' "--dpi-desync=multisplit"
        printf '%s\n' "--dpi-desync-split-seqovl=681"
        printf '%s\n' "--dpi-desync-split-pos=1"
      } > "$path"
      ;;
    general-alt10)
      {
        printf '%s\n' "--qnum=$strategy_queue"
        printf '%s\n' "--filter-tcp=80,443"
        printf '%s\n' "--hostlist-domains=$domain"
        printf '%s\n' "--dpi-desync=fake"
        printf '%s\n' "--dpi-desync-repeats=6"
        printf '%s\n' "--dpi-desync-fooling=ts"
      } > "$path"
      ;;
    *) die "unknown built-in quick strategy: $profile" ;;
  esac
  chmod 600 "$path"
}

profile_name() {
  case "$1" in
    general) printf '%s\n' 'General' ;;
    general-alt) printf '%s\n' 'General [ALT]' ;;
    general-alt2) printf '%s\n' 'General [ALT2]' ;;
    general-alt4) printf '%s\n' 'General [ALT4]' ;;
    general-alt6) printf '%s\n' 'General [ALT6]' ;;
    general-alt10) printf '%s\n' 'General [ALT10]' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

json_quote_file() {
  # Preserve the strategy bytes exactly, including the trailing newline that
  # write_strategy emits. Omitting it makes strategy_digest disagree with the
  # bytes later loaded by LoadCatalogFile.
  awk 'BEGIN { printf "\"" } { gsub(/\\/, "\\\\"); gsub(/\"/, "\\\""); printf "%s", $0; printf "\\n" } END { printf "\"" }' "$1"
}

provider_version=$($NFQWS_BIN --version 2>&1 | sed -n '1s/.*version v\{0,1\}\([0-9][0-9.]*\).*/\1/p')
case "$provider_version" in ""|*[!0-9.]*|.*|*..*|*.) die "unable to determine pinned nfqws version" ;; esac
binary_digest=$(sha256sum "$NFQWS_BIN" | awk '{print $1}')
case "$binary_digest" in ""|*[!0-9a-fA-F]*) die "unable to determine nfqws binary digest" ;; esac

profiles="general general-alt general-alt2 general-alt4 general-alt6 general-alt10"
[ -n "$MANAGED_QUEUE" ] || die "managed production NFQUEUE is required"
case "$MANAGED_QUEUE" in ""|*[!0-9]*) die "invalid managed production NFQUEUE" ;; esac
[ "$MANAGED_QUEUE" -ge 1 ] && [ "$MANAGED_QUEUE" -le 65535 ] || die "managed production NFQUEUE is outside the valid range"
allocate_queue
profile_count=0
{
  printf '{"version":1,"profiles":['
  for profile in $profiles; do
    [ "$profile_count" -eq 0 ] || printf ','
    # Keep the production artifact (bound to the managed queue) separate from
    # the per-attempt test artifact (bound to the private queue below).  A
    # single path here would let the attempt overwrite the bytes whose digest
    # is published in the catalog, creating false evidence.
    catalog_strategy_path="$run_dir/$profile.catalog.conf"
    write_strategy "$profile" "$catalog_strategy_path" "$MANAGED_QUEUE"
    strategy_digest=$(sha256sum "$catalog_strategy_path" | awk '{print $1}')
    profile_label=$(profile_name "$profile")
    printf '{"id":"%s","name":"%s","provider":"nfqws-v1","provider_version":"%s","binary_digest":"sha256:%s","route_type":"zapret","ip_families":["ipv4"],"transports":["tcp"],"ports":[80,443],"queue":%s,"safety":"reviewed","strategy_digest":"sha256:%s","strategy":' "$profile" "$profile_label" "$provider_version" "$binary_digest" "$MANAGED_QUEUE" "$strategy_digest"
    json_quote_file "$catalog_strategy_path"
    printf '}'
    profile_count=$((profile_count + 1))
  done
  printf '],"bundles":[{"id":"%s","category":"TSPU_RESTRICTED","required_domains":["%s"],"protocols":[{"transport":"tcp","port":80},{"transport":"tcp","port":443}],"ip_families":["ipv4"],"allowed_profiles":["general","general-alt","general-alt2","general-alt4","general-alt6","general-alt10"],"failure_route":"drop"}]}' "$bundle_id" "$domain"
} > "$catalog_tmp"

mv "$catalog_tmp" "$catalog_file"
catalog_tmp=""

append_attempt() {
  profile="$1"
  result="$2"
  path_ok="$3"
  cleanup_ok="$4"
  evidence="$5"
  packets="$6"
  counter_delta="$7"
  latency_ms="$8"
  duration_ms="$9"
  http_status="${10}"
  error_code="${11}"
  error_text="${12}"
  [ "$attempt_count" -eq 0 ] || printf ',\n' >> "$attempts_file"
  profile_label=$(profile_name "$profile")
  printf '{"profile_id":"%s","profile_name":"%s","target":"%s","protocol":"https","result":"%s","path_verified":%s,"cleanup_verified":%s,"route_evidence":"%s","probe_privilege_mode":"%s","probe_uid":%s,"nfqueue_packets":%s,"nfqueue_counter_delta":%s,"latency_ms":%s,"verification_duration_ms":%s,"http_status":%s' \
    "$profile" "$profile_label" "$domain" "$result" "$path_ok" "$cleanup_ok" "$evidence" "$probe_mode" "$probe_user" "$packets" "$counter_delta" "$latency_ms" "$duration_ms" "$http_status" >> "$attempts_file"
  if [ -n "$error_code" ]; then
    printf ',"error_code":"%s"' "$error_code" >> "$attempts_file"
  fi
  if [ -n "$error_text" ]; then
    printf ',"error":"%s"' "$error_text" >> "$attempts_file"
  fi
  printf '}' >> "$attempts_file"
  attempt_count=$((attempt_count + 1))
  if [ "$path_ok" = "true" ] && [ "$result" = "PASS" ]; then
    path_verified_count=$((path_verified_count + 1))
  fi
}

counter_packets() {
  output=$($NFT_BIN list table inet "$table" 2>/dev/null) || return 1
  printf '%s\n' "$output" | awk '/router-policy-calibration owner=/{for (i = 1; i <= NF; i++) if ($i == "packets") total += $(i + 1)} END {print total + 0}'
}

install_probe_table() {
  ips="$1"
  rules="$run_dir/$profile.rules.nft"
  {
    printf 'table inet %s {\n' "$table"
    printf '  chain probe_output { type filter hook output priority -300; policy accept;\n'
    old_ifs=$IFS
    IFS=,
    for ip in $ips; do
      printf '    meta skuid %s ip daddr %s tcp dport { 80, 443 } counter queue num %s comment "router-policy-calibration owner=%s"\n' "$probe_user" "$ip" "$queue" "$run_token"
    done
    IFS=$old_ifs
    printf '  }\n}\n'
  } > "$rules"
  # stdout is the machine-readable result channel.  nft may print warnings or
  # BusyBox usage text even when the command fails; route every diagnostic to
  # stderr so a failed attempt can never corrupt the bounded JSON document.
  $NFT_BIN -f "$rules" >&2 || return 1
  $NFT_BIN list table inet "$table" >/dev/null 2>&1 || return 1
}

start_nfqwss() {
  strategy_path="$1"
  log_path="$2"
  ROUTER_POLICY_CALIBRATION_RUN_ID="$run_token" "$SETSID_BIN" "$NFQWS_BIN" "@$strategy_path" > "$log_path" 2>&1 &
  nfq_pid=$!
  sleep 1
  kill -0 "$nfq_pid" 2>/dev/null || return 1
  nfq_pgid=$(proc_pgid "$nfq_pid")
  case "$nfq_pgid" in ""|0|*[!0-9]*) return 1 ;; esac
  controller_pgid=$(proc_pgid "$$")
  [ "$nfq_pgid" != "$controller_pgid" ] || return 1
  [ "$(proc_exe "$nfq_pid")" = "$NFQWS_BIN" ] || return 1
  command_line=$(proc_cmdline "$nfq_pid")
  case "$command_line" in
    *"@$strategy_path"*) ;;
    *) return 1 ;;
  esac
  start_parent_watchdog
}

start_parent_watchdog() {
  owner_pid="$$"
  owner_start=$(proc_start_time "$owner_pid" 2>/dev/null || printf '')
  watched_pgid="$nfq_pgid"
  watched_table="$table"
  watched_strategy="$strategy_path"
  watched_run_dir="$run_dir"
  (
    while [ -r "/proc/$owner_pid/stat" ]; do
      current_start=$(proc_start_time "$owner_pid" 2>/dev/null || printf '')
      [ -n "$owner_start" ] && [ "$current_start" = "$owner_start" ] || break
      sleep 1
    done
    # timeout(1) may kill this shell without running its EXIT trap.  The
    # watchdog then removes only this attempt's process group/table/files.
    if [ -n "$watched_pgid" ] && [ "$watched_pgid" != "0" ]; then
      kill -TERM "-$watched_pgid" 2>/dev/null || true
      sleep 1
      kill -KILL "-$watched_pgid" 2>/dev/null || true
    fi
    if [ -n "$watched_strategy" ]; then
      for proc in /proc/[0-9]*; do
        [ -r "$proc/cmdline" ] || continue
        pid=${proc#/proc/}
        [ "$(proc_exe "$pid")" = "$NFQWS_BIN" ] || continue
        command_line=$(proc_cmdline "$pid")
        case "$command_line" in
          *"@$watched_strategy"*) kill -KILL "$pid" 2>/dev/null || true ;;
          *)
            if [ -r "/proc/$pid/environ" ] && tr '\000' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -Fqx -- "ROUTER_POLICY_CALIBRATION_RUN_ID=$run_token"; then
              kill -KILL "$pid" 2>/dev/null || true
            fi
            ;;
        esac
      done
    fi
    if [ -n "$watched_table" ] && $NFT_BIN list table inet "$watched_table" >/dev/null 2>&1; then
      $NFT_BIN delete table inet "$watched_table" >/dev/null 2>&1 || true
    fi
    [ -n "$watched_run_dir" ] && rm -rf "$watched_run_dir"
  ) &
  watchdog_pid=$!
}

stop_parent_watchdog() {
  if [ -n "$watchdog_pid" ]; then
    kill -TERM "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    watchdog_pid=""
  fi
}

cleanup_attempt() {
  local_status=0
  stop_parent_watchdog
  if [ -n "$table" ]; then
    if $NFT_BIN list table inet "$table" >/dev/null 2>&1; then
      $NFT_BIN delete table inet "$table" >/dev/null 2>&1 || local_status=1
    fi
    if $NFT_BIN list table inet "$table" >/dev/null 2>&1; then
      local_status=1
    fi
  fi
  if [ -n "$nfq_pgid" ]; then
    controller_pgid=$(proc_pgid "$$")
    if [ "$nfq_pgid" = "$controller_pgid" ] || [ "$nfq_pgid" = "0" ]; then
      local_status=1
    else
      kill -TERM "-$nfq_pgid" 2>/dev/null || true
      wait_count=0
      while group_exists "$nfq_pgid" && [ "$wait_count" -lt 5 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
      done
      if group_exists "$nfq_pgid"; then
        kill -KILL "-$nfq_pgid" 2>/dev/null || true
        sleep 1
      fi
      group_exists "$nfq_pgid" && local_status=1
    fi
  elif [ -n "$nfq_pid" ]; then
    if [ "$(proc_exe "$nfq_pid")" = "$NFQWS_BIN" ]; then
      kill -TERM "$nfq_pid" 2>/dev/null || true
      sleep 1
      kill -0 "$nfq_pid" 2>/dev/null && kill -KILL "$nfq_pid" 2>/dev/null || true
      kill -0 "$nfq_pid" 2>/dev/null && local_status=1
    else
      local_status=1
    fi
  fi
  cleanup_owned_nfqwss || local_status=1
  if $NFT_BIN list ruleset 2>/dev/null | grep -Fq "router-policy-calibration owner=$run_token"; then
    local_status=1
  fi
  nfq_pid=""
  nfq_pgid=""
  table=""
  return "$local_status"
}

capture_network_baseline() {
  "$IP_BIN" route show table all > "$run_dir/routes.before" 2>"$run_dir/routes.before.err" || return 1
  "$IP_BIN" rule show > "$run_dir/rules.before" 2>"$run_dir/rules.before.err" || return 1
}

verify_network_baseline() {
  "$IP_BIN" route show table all > "$run_dir/routes.after" 2>"$run_dir/routes.after.err" || return 1
  "$IP_BIN" rule show > "$run_dir/rules.after" 2>"$run_dir/rules.after.err" || return 1
  cmp -s "$run_dir/routes.before" "$run_dir/routes.after" || return 1
  cmp -s "$run_dir/rules.before" "$run_dir/rules.after" || return 1
}

route_evidence() {
  output=$("$IP_BIN" route get "$1" 2>/dev/null) || return 1
  # Keep evidence bounded and safe for the machine-readable JSON string.
  route_evidence_value=$(printf '%s' "$output" | tr '\r\n\t' '   ' | cut -c1-512 | sed 's/\\/\\\\/g; s/"/\\"/g')
  [ -n "$route_evidence_value" ]
}

capture_network_baseline || die "unable to capture route/rule baseline"

probe_once() {
  profile="$1"
  ip="$2"
  route_evidence_value=""
  out="$run_dir/$profile-$attempt_index.curl"
  errfile="$run_dir/$profile-$attempt_index.curl.log"
  if ! route_evidence "$ip"; then
    result="INFRA_ERROR"
    path_ok=false
    error_code="route_unavailable"
    error_text="kernel route lookup for the verified target failed"
    return 0
  fi
  command_string="$(shell_quote "$CURL_BIN") --silent --show-error --noproxy '*' --connect-timeout 5 --max-time 12 --output /dev/null --write-out '%{http_code}|%{time_total}' --resolve $(shell_quote "$domain:443:$ip") $(shell_quote "https://$domain/")"
  set +e
  if [ "$probe_mode" = "unprivileged" ]; then
    "$SU_BIN" -s /bin/sh "$PROBE_USER" -c "$command_string" > "$out" 2> "$errfile"
  else
    /bin/sh -c "$command_string" > "$out" 2> "$errfile"
  fi
  curl_status=$?
  set -e
  [ -n "$nfq_pid" ] && kill -0 "$nfq_pid" 2>/dev/null || curl_status=125
  counter_delta=$(counter_packets) || counter_delta=0
  case "$counter_delta" in ""|*[!0-9]*) counter_delta=0 ;; esac
  packets="$counter_delta"
  http_status=0
  latency_ms=0
  if [ -s "$out" ]; then
    http_status=$(sed -n 's/^\([0-9][0-9][0-9]\)|.*/\1/p' "$out" | tail -n 1)
    total_seconds=$(sed -n 's/^[0-9][0-9][0-9]|\([0-9.]*\)$/\1/p' "$out" | tail -n 1)
    case "$http_status" in ""|*[!0-9]*) http_status=0 ;; esac
    # curl uses the sentinel HTTP status `000` when no response was
    # received.  It is a string at the command boundary, but printing it as
    # a JSON number would produce invalid JSON (numbers may not have leading
    # zeroes).  Canonicalise every decimal status before serialising it.
    http_status=$(printf '%s' "$http_status" | sed 's/^0*//')
    [ -n "$http_status" ] || http_status=0
    case "$total_seconds" in
      ''|*[!0-9.]*) latency_ms=0 ;;
      *) latency_ms=$(awk -v seconds="$total_seconds" 'BEGIN { printf "%d", seconds * 1000 }') ;;
    esac
  fi
  if [ "$counter_delta" -eq 0 ]; then
    result="INFRA_ERROR"
    path_ok=false
    error_code="path_not_observed"
    error_text="test request did not increment the owned NFQUEUE counter"
  elif [ "$curl_status" -eq 28 ]; then
    result="TIMEOUT"
    path_ok=true
    error_code="curl_timeout"
    error_text="bounded HTTPS request timed out after path observation"
  elif [ "$curl_status" -eq 0 ] && [ "$http_status" -ge 200 ] && [ "$http_status" -lt 400 ]; then
    result="PASS"
    path_ok=true
    error_code=""
    error_text=""
  else
    result="FAIL"
    path_ok=true
    error_code="http_or_transport_failed"
    error_text="HTTPS request returned no acceptable response"
  fi
  return 0
}

addresses="${ZAPRET_CALIBRATION_IPV4:-}"
[ -n "$addresses" ] || die "verified IPv4 targets are required for a path-bound quick check"
old_ifs=$IFS
IFS=,
address_count=0
selected_addresses=""
for address in $addresses; do
  case "$address" in
    *[!0-9.]*) die "invalid pre-resolved IPv4 target" ;;
  esac
  if ! printf '%s\n' "$address" | awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1; next } { exit 1 }'; then
    die "invalid pre-resolved IPv4 target"
  fi
  [ "$address_count" -lt "$MAX_ADDRESSES" ] || break
  [ "$address_count" -eq 0 ] || selected_addresses="$selected_addresses,"
  selected_addresses="$selected_addresses$address"
  address_count=$((address_count + 1))
done
IFS=$old_ifs
[ "$address_count" -gt 0 ] || die "no verified IPv4 target was supplied"

for profile in $profiles; do
  attempt_index=$((attempt_index + 1))
  strategy_path="$run_dir/$profile.test.conf"
  write_strategy "$profile" "$strategy_path" "$queue"
  dry_path="$run_dir/$profile.dry.conf"
  cp "$strategy_path" "$dry_path"
  printf '%s\n' '--dry-run' >> "$dry_path"
  if ! "$NFQWS_BIN" "@$dry_path" >/dev/null 2>&1; then
    append_attempt "$profile" "INFRA_ERROR" false true "strategy_validation" 0 0 0 0 0 "strategy_invalid" "nfqws rejected the curated strategy"
    continue
  fi
  table="rpq_${run_token}_${attempt_index}"
  start_ms=$(now_ms) || die "clock unavailable for bounded verification duration"
  if ! start_nfqwss "$strategy_path" "$run_dir/$profile.nfqws.log"; then
    cleanup_attempt || die "unable to clean failed nfqws start"
    verify_network_baseline || die "quick calibration cleanup changed routes or rules after failed nfqws start"
    append_attempt "$profile" "INFRA_ERROR" false true "process_group" 0 0 0 0 0 "nfqws_process_unbound" "nfqws process group could not be proven"
    continue
  fi
  if ! install_probe_table "$selected_addresses"; then
    cleanup_attempt || die "unable to clean failed nft installation"
    verify_network_baseline || die "quick calibration cleanup changed routes or rules after failed nft installation"
    append_attempt "$profile" "INFRA_ERROR" false true "nft_owned_table" 0 0 0 0 0 "nft_transition_failed" "owned temporary output table could not be installed"
    continue
  fi
  probe_status="INFRA_ERROR"
  path_ok=false
  cleanup_ok=false
  evidence=""
  packets=0
  counter_delta=0
  latency_ms=0
  duration_ms=0
  http_status=0
  error_code="path_not_observed"
  error_text="no target was probed"
  old_ifs=$IFS
  IFS=,
  for address in $selected_addresses; do
    probe_once "$profile" "$address"
    if [ "$result" = "PASS" ]; then
      probe_status="$result"
      evidence="owned_nft_queue=$queue;production_nfqueue=$MANAGED_QUEUE;nfqws_pid=$nfq_pid;target_ip=$address;route=$route_evidence_value"
      break
    fi
    probe_status="$result"
    evidence="owned_nft_queue=$queue;production_nfqueue=$MANAGED_QUEUE;nfqws_pid=$nfq_pid;target_ip=$address;route=$route_evidence_value"
  done
  IFS=$old_ifs
  end_ms=$(now_ms) || die "clock unavailable for bounded verification duration"
  duration_ms=$((end_ms - start_ms))
  if cleanup_attempt; then
    cleanup_ok=true
  else
    die "quick calibration cleanup proof failed for $profile"
  fi
  [ "$cleanup_ok" = "true" ] || die "quick calibration cleanup proof failed for $profile"
  verify_network_baseline || die "quick calibration cleanup changed routes or rules for $profile"
  append_attempt "$profile" "$probe_status" "$path_ok" "$cleanup_ok" "$evidence" "$packets" "$counter_delta" "$latency_ms" "$duration_ms" "$http_status" "$error_code" "$error_text"
done

mkdir -p "$(dirname "$CATALOG_OUT")"
[ ! -L "$CATALOG_OUT" ] || die "catalog output is a symlink"
catalog_tmp="$CATALOG_OUT.tmp.$run_token"
cp "$catalog_file" "$catalog_tmp"
chmod 600 "$catalog_tmp"
mv "$catalog_tmp" "$CATALOG_OUT"
catalog_tmp=""

path_value=false
[ "$path_verified_count" -gt 0 ] && path_value=true
{
  printf '{"catalog":'
  cat "$catalog_file"
  printf ',"evidence_level":"path_verified","path_verified":%s,"attempts":[' "$path_value"
  cat "$attempts_file"
  printf ']}\n'
} > "$run_dir/result.json"
cat "$run_dir/result.json"
