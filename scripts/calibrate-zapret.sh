#!/bin/sh
set -eu

CONFIG="${ROUTER_POLICY_CONFIG:-/etc/router-policy/config/default.json}"
ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-/usr/bin/router-policy}"
NFQWS_BIN="${NFQWS_BIN:-/usr/bin/nfqws}"
ZAPRET_INIT="${ZAPRET_INIT:-/etc/init.d/router-policy-zapret}"
RUNTIME_DIR="${ROUTER_POLICY_RUNTIME_DIR:-/tmp/router-policy}"
CATALOG_OUT="${ZAPRET_CATALOG_OUT:-/etc/router-policy/zapret/catalog.json}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
BLOCKCHECK_TIMEOUT="${BLOCKCHECK_TIMEOUT:-}"
QUEUE_NUM="${ZAPRET_QUEUE_NUM:-200}"
PRE_RESOLVED_IPV4="${ZAPRET_CALIBRATION_IPV4:-}"

mode="dry-run"
calibration_mode="quick"
domain=""
bundle_id=""
network_fingerprint=""
blockcheck_script="${BLOCKCHECK_SCRIPT:-}"
allow_managed_restart=0

usage() {
  echo "usage: calibrate-zapret.sh [--dry-run|--apply] [--mode quick|exhaustive] --domain DOMAIN --bundle-id ID --network-fingerprint sha256:HEX --blockcheck FILE [--allow-managed-restart]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) mode="dry-run" ;;
    --apply) mode="apply" ;;
    --mode) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; calibration_mode="$1" ;;
    --domain) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; domain="$1" ;;
    --bundle-id) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; bundle_id="$1" ;;
    --network-fingerprint) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; network_fingerprint="$1" ;;
    --blockcheck) shift; [ "$#" -gt 0 ] || { usage; exit 2; }; blockcheck_script="$1" ;;
    --allow-managed-restart) allow_managed_restart=1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

case "$domain" in
  ""|.*|-*|*..*|*[!A-Za-z0-9.-]*) echo "invalid calibration domain" >&2; exit 2 ;;
esac
[ "${#domain}" -le 253 ] || { echo "calibration domain is too long" >&2; exit 2; }
case "$bundle_id" in
  ""|*[!A-Za-z0-9._-]*) echo "invalid calibration bundle ID" >&2; exit 2 ;;
esac
[ "${#bundle_id}" -le 96 ] || { echo "calibration bundle ID is too long" >&2; exit 2; }
case "$QUEUE_NUM" in
  ""|*[!0-9]*) echo "invalid Zapret queue number" >&2; exit 2 ;;
esac
[ "$QUEUE_NUM" -ge 1 ] && [ "$QUEUE_NUM" -le 65535 ] || { echo "invalid Zapret queue number" >&2; exit 2; }
case "$network_fingerprint" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "network fingerprint must be a sha256 digest" >&2; exit 2 ;;
esac
fingerprint_hex=${network_fingerprint#sha256:}
case "$fingerprint_hex" in
  *[!0-9a-fA-F]*) echo "network fingerprint must be hexadecimal" >&2; exit 2 ;;
esac
[ -n "$blockcheck_script" ] || { echo "upstream blockcheck path is required" >&2; exit 2; }
case "$calibration_mode" in
  quick)
    scan_level="quick"
    [ -n "$BLOCKCHECK_TIMEOUT" ] || BLOCKCHECK_TIMEOUT=300
    ;;
  exhaustive)
    scan_level="force"
    [ -n "$BLOCKCHECK_TIMEOUT" ] || BLOCKCHECK_TIMEOUT=21600
    ;;
  *) echo "calibration mode must be quick or exhaustive" >&2; exit 2 ;;
esac
case "$BLOCKCHECK_TIMEOUT" in
  ""|*[!0-9]*) echo "blockcheck timeout must be an integer number of seconds" >&2; exit 2 ;;
esac
max_blockcheck_timeout=21600
[ "$BLOCKCHECK_TIMEOUT" -ge 1 ] && [ "$BLOCKCHECK_TIMEOUT" -le "$max_blockcheck_timeout" ] || {
  echo "blockcheck timeout must be between 1 and ${max_blockcheck_timeout} seconds" >&2
  exit 2
}

if [ "$mode" = "dry-run" ]; then
  echo "mode=dry-run"
  echo "calibration_mode=$calibration_mode"
  echo "scan_level=$scan_level"
  echo "timeout_seconds=$BLOCKCHECK_TIMEOUT"
  echo "domain=$domain"
  echo "bundle_id=$bundle_id"
  if [ "$calibration_mode" = "quick" ]; then
    echo "quick_requires_curated_runner=true"
    echo "would_run_upstream_blockcheck=false"
  else
    echo "would_run_upstream_blockcheck=$blockcheck_script"
  fi
  echo "would_store_top_candidates=$CATALOG_OUT"
  echo "would_not_activate_candidate=true"
  exit 0
fi

if [ "$calibration_mode" = "quick" ]; then
  echo "quick calibration requires the separate curated dataplane evidence runner; upstream blockcheck is exhaustive-only" >&2
  exit 78
fi

[ "$(id -u)" = "0" ] || { echo "Zapret calibration requires root" >&2; exit 1; }
case "$TIMEOUT_BIN" in
  /*) ;;
  *)
    resolved_timeout=$(command -v "$TIMEOUT_BIN") || {
      echo "required executable is unavailable: $TIMEOUT_BIN" >&2
      exit 1
    }
    TIMEOUT_BIN="$resolved_timeout"
    ;;
esac
if [ -L "$TIMEOUT_BIN" ]; then
  resolved_timeout=$(readlink -f "$TIMEOUT_BIN") || {
    echo "unable to resolve timeout executable: $TIMEOUT_BIN" >&2
    exit 1
  }
  TIMEOUT_BIN="$resolved_timeout"
fi
for command in "$ROUTER_POLICY_BIN" "$NFQWS_BIN" "$TIMEOUT_BIN"; do
  [ -x "$command" ] || { echo "required executable is unavailable: $command" >&2; exit 1; }
  [ ! -L "$command" ] || { echo "refusing symlink executable: $command" >&2; exit 1; }
done
[ -f "$blockcheck_script" ] && [ ! -L "$blockcheck_script" ] || {
  echo "upstream blockcheck must be a regular non-symlink file" >&2
  exit 1
}
[ -x "$ZAPRET_INIT" ] || { echo "FlintRoute Zapret service is unavailable" >&2; exit 1; }

mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
lock_dir="$RUNTIME_DIR/zapret-calibration.lock"
mkdir "$lock_dir" 2>/dev/null || { echo "another Zapret calibration is active" >&2; exit 1; }
run_dir="$RUNTIME_DIR/zapret-calibration.$$"
mkdir "$run_dir"
chmod 700 "$run_dir"
process_manifest="$run_dir/processes.txt"
nfqws_baseline="$run_dir/nfqws.before"
routes_baseline="$run_dir/routes.before"
rules_baseline="$run_dir/rules.before"
report="$run_dir/blockcheck.log"
result="$run_dir/import.json"
blockcheck_pid_file="$run_dir/blockcheck.pid"
blockcheck_status_file="$run_dir/blockcheck.status"
maintenance_started=0
zapret_was_running=0
blockcheck_pid=""
blockcheck_pgid=""
calibration_pgid=""
calibration_run_id="calibration-$$"

proc_start_time() {
  pid="$1"
  [ -r "/proc/$pid/stat" ] || return 1
  awk '{print $22}' "/proc/$pid/stat" 2>/dev/null
}

proc_executable() {
  pid="$1"
  readlink "/proc/$pid/exe" 2>/dev/null || true
}

proc_commandline() {
  pid="$1"
  tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true
}

proc_has_calibration_marker() {
  pid="$1"
  [ -r "/proc/$pid/environ" ] || return 1
  tr '\000' '\n' < "/proc/$pid/environ" 2>/dev/null \
    | grep -Fqx "ROUTER_POLICY_CALIBRATION_RUN_ID=$calibration_run_id"
}

proc_pgid() {
  pid="$1"
  ps -o pgid= -p "$pid" 2>/dev/null | awk '{print $1}'
}

proc_ppid() {
  pid="$1"
  ps -o ppid= -p "$pid" 2>/dev/null | awk '{print $1}'
}

process_group_exists() {
  pgid="$1"
  case "$pgid" in
    ""|*[!0-9]*) return 1 ;;
  esac
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    pid=${proc#/proc/}
    [ "$(proc_pgid "$pid")" = "$pgid" ] && return 0
  done
  return 1
}

list_nfqwss() {
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    pid=${proc#/proc/}
    exe=$(proc_executable "$pid")
    commandline=$(proc_commandline "$pid")
    case "$exe:$commandline" in
      "$NFQWS_BIN":*|*/nfqws:*|*"$NFQWS_BIN"*|*"/nfqws "*)
        start=$(proc_start_time "$pid") || continue
        # The ownership snapshot intentionally contains only the identity used
        # for PID-reuse protection.  PGID/PPID/argv are queried live when the
        # cleanup decision is made, so they cannot make the snapshot parser
        # confuse an executable path with trailing fields.
        printf '%s|%s|%s\n' "$pid" "$start" "$exe"
        ;;
    esac
  done
}

same_process() {
  pid="$1"; start="$2"; exe="$3"
  [ -d "/proc/$pid" ] || return 1
  [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" != "Z" ] || return 1
  [ "$(proc_start_time "$pid")" = "$start" ] || return 1
  [ "$(proc_executable "$pid")" = "$exe" ]
}

terminate_owned_process() {
  pid="$1"; start="$2"; exe="$3"
  same_process "$pid" "$start" "$exe" || return 0
  kill -TERM "$pid" 2>/dev/null || true
  i=0
  while [ "$i" -lt 10 ] && same_process "$pid" "$start" "$exe"; do
    sleep 1
    i=$((i + 1))
  done
  if same_process "$pid" "$start" "$exe"; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
}

cleanup_owned_nfqwss() {
	current="$run_dir/nfqws.after"
	list_nfqwss > "$current" || return 1
while IFS='|' read -r pid start exe; do
    [ -n "$pid" ] || continue
    baseline=0
    while IFS='|' read -r old_pid old_start old_exe; do
      if [ "$pid" = "$old_pid" ] && [ "$start" = "$old_start" ] && [ "$exe" = "$old_exe" ]; then
        baseline=1
        break
      fi
    done < "$nfqws_baseline"
	    if [ "$baseline" != "1" ]; then
	      pgid=$(proc_pgid "$pid")
	      if [ -z "$calibration_pgid" ] || [ "$pgid" != "$calibration_pgid" ]; then
	        # A provider is allowed to daemonize, which creates a new session and
	        # makes the process-group proof disappear.  The child still inherits
	        # the per-run marker exported below.  Kill only when that independent
	        # ownership proof matches; an unmarked process remains foreign and
	        # cleanup fails closed instead of guessing.
	        if ! proc_has_calibration_marker "$pid"; then
	          echo "new nfqws has no provable calibration ownership: $pid" >&2
	          return 1
	        fi
	      fi
	      terminate_owned_process "$pid" "$start" "$exe"
	    fi
	done < "$current"
}

verify_no_owned_nfqwss() {
  remaining="$run_dir/nfqws.remaining"
  list_nfqwss > "$remaining" || return 1
  while IFS='|' read -r pid start exe; do
    [ -n "$pid" ] || continue
    baseline=0
    while IFS='|' read -r old_pid old_start old_exe; do
      if [ "$pid" = "$old_pid" ] && [ "$start" = "$old_start" ] && [ "$exe" = "$old_exe" ]; then
        baseline=1
        break
      fi
    done < "$nfqws_baseline"
    if [ "$baseline" != "1" ]; then
      pgid=$(proc_pgid "$pid")
      echo "calibration cleanup left an unowned/new nfqws process: $pid pgid=$pgid" >&2
      return 1
    fi
  done < "$remaining"
}

verify_calibration_network_cleanup() {
  if command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -Fq "router-policy-calibration owner=$calibration_run_id"; then
      echo "calibration cleanup left an NFQUEUE/nft resource" >&2
      return 1
    fi
  fi
  if command -v ip >/dev/null 2>&1; then
    ip -o route show table all 2>/dev/null > "$run_dir/routes.after" || return 1
    ip -o rule show 2>/dev/null > "$run_dir/rules.after" || return 1
    if ! cmp -s "$routes_baseline" "$run_dir/routes.after"; then
      echo "calibration cleanup changed routing tables" >&2
      return 1
    fi
    if ! cmp -s "$rules_baseline" "$run_dir/rules.after"; then
      echo "calibration cleanup changed policy rules" >&2
      return 1
    fi
  fi
  return 0
}

list_nfqwss > "$nfqws_baseline"
if command -v ip >/dev/null 2>&1; then
  ip -o route show table all 2>/dev/null > "$routes_baseline" || exit 1
  ip -o rule show 2>/dev/null > "$rules_baseline" || exit 1
else
  : > "$routes_baseline"
  : > "$rules_baseline"
fi

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  calibration_pgid="$blockcheck_pgid"
  if [ -n "$blockcheck_pgid" ]; then
    controller_pgid=$(proc_pgid "$$" 2>/dev/null || true)
    if [ "$blockcheck_pgid" = "$controller_pgid" ]; then
      echo "refusing to signal the calibration controller process group: $blockcheck_pgid" >&2
      status=1
    else
      kill -TERM "-$blockcheck_pgid" 2>/dev/null || true
      i=0
      while [ "$i" -lt 10 ] && process_group_exists "$blockcheck_pgid"; do
        sleep 1
        i=$((i + 1))
      done
      if process_group_exists "$blockcheck_pgid"; then
        kill -KILL "-$blockcheck_pgid" 2>/dev/null || true
        i=0
        while [ "$i" -lt 5 ] && process_group_exists "$blockcheck_pgid"; do
          sleep 1
          i=$((i + 1))
        done
        if process_group_exists "$blockcheck_pgid"; then
          echo "calibration process group survived cleanup: $blockcheck_pgid" >&2
          status=1
        fi
      fi
    fi
    blockcheck_pgid=""
    blockcheck_pid=""
  fi
  cleanup_owned_nfqwss || status=1
  verify_no_owned_nfqwss || status=1
  verify_calibration_network_cleanup || status=1
  if [ "$zapret_was_running" = "1" ]; then
    "$TIMEOUT_BIN" 30 "$ZAPRET_INIT" start >/dev/null 2>&1 || status=1
  fi
  if [ "$maintenance_started" = "1" ]; then
    ROUTER_POLICY_CONFIG="$CONFIG" "$TIMEOUT_BIN" 15 "$ROUTER_POLICY_BIN" maintenance end >/dev/null 2>&1 || status=1
  fi
  rm -rf "$run_dir"
  rmdir "$lock_dir" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

if "$TIMEOUT_BIN" 10 "$ZAPRET_INIT" running >/dev/null 2>&1; then
  [ "$allow_managed_restart" = "1" ] || {
    echo "managed Zapret is active; repeat with --allow-managed-restart during a maintenance window" >&2
    exit 1
  }
  zapret_was_running=1
fi

ROUTER_POLICY_CONFIG="$CONFIG" "$TIMEOUT_BIN" 15 "$ROUTER_POLICY_BIN" maintenance begin \
  --owner "installer:zapret-calibration" --reason "provider-specific Zapret calibration" --lease 45m >/dev/null
maintenance_started=1

if [ "$zapret_was_running" = "1" ]; then
  "$TIMEOUT_BIN" 30 "$ZAPRET_INIT" stop
fi

provider_version=$("$TIMEOUT_BIN" 10 "$NFQWS_BIN" --version 2>&1 | sed -n '1s/.*version v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | cut -c1-32)
[ -n "$provider_version" ] || { echo "unable to determine nfqws version" >&2; exit 1; }
case "$provider_version" in
  *[!0-9.]*|.*|*..*|*.) echo "nfqws returned an invalid version" >&2; exit 1 ;;
esac

skip_dnscheck=0
if [ -n "$PRE_RESOLVED_IPV4" ]; then
  case "$PRE_RESOLVED_IPV4" in
    *[!0-9.,]*) echo "invalid pre-resolved calibration address list" >&2; exit 2 ;;
  esac
  hostvar=$(printf '%s' "$domain" | sed 's/[.-]/_/g')
  addresses=$PRE_RESOLVED_IPV4
  set --
  while [ -n "$addresses" ]; do
    case "$addresses" in
      *,*) address=${addresses%%,*}; addresses=${addresses#*,} ;;
      *) address=$addresses; addresses= ;;
    esac
    set -- "$@" "$address"
  done
  [ "$#" -ge 1 ] && [ "$#" -le 8 ] || { echo "invalid pre-resolved calibration address count" >&2; exit 2; }
  address_index=0
  for address in "$@"; do
    old_ifs=$IFS
    IFS=.
    read -r octet1 octet2 octet3 octet4 octet5 <<EOF
$address
EOF
    IFS=$old_ifs
    [ -n "$octet1" ] && [ -n "$octet2" ] && [ -n "$octet3" ] && [ -n "$octet4" ] && [ -z "$octet5" ] || { echo "invalid pre-resolved calibration IPv4 address" >&2; exit 2; }
    for octet in "$octet1" "$octet2" "$octet3" "$octet4"; do
      case "$octet" in
        ""|*[!0-9]*) echo "invalid pre-resolved calibration IPv4 address" >&2; exit 2 ;;
      esac
      [ "$octet" -le 255 ] || { echo "invalid pre-resolved calibration IPv4 address" >&2; exit 2; }
    done
    eval "export DNSCACHE_${hostvar}_4_${address_index}=$address"
    address_index=$((address_index + 1))
  done
  eval "export DNSCACHE_${hostvar}_4_COUNT=$address_index"
  skip_dnscheck=1
fi

command -v setsid >/dev/null 2>&1 || {
  echo "setsid is required to isolate calibration process ownership" >&2
  exit 1
}
export ROUTER_POLICY_CALIBRATION_RUN_ID="$calibration_run_id"
set +e
# shellcheck disable=SC2016 # the child shell expands its positional arguments.
setsid sh -c '
  # setsid may fork when its caller is already a process-group leader.  The
  # background PID is then the short-lived launcher, not the isolated child;
  # publish the child PID from inside the new session instead of trusting $!.
  printf "%s\\n" "$$" > "${11}"
  # Stop before executing provider code. This gives the controller a stable
  # PID/PGID to validate, even when the blockcheck exits immediately.
  kill -STOP "$$"
  cd "$1"
  NFQWS="$8" NFQWS_BIN="$8" ROUTER_POLICY_CALIBRATION_RUN_ID="$9" \
    BATCH=1 IPVS=4 REPEATS=3 SCANLEVEL="${10}" SKIP_TPWS=1 SKIP_DNSCHECK="$2" DOMAINS="$3" \
    "$4" "$5" sh "$6" >"$7" 2>&1
  status=$?
  printf "%s\\n" "$status" > "${12}"
  exit "$status"
' sh "$(dirname "$blockcheck_script")" "$skip_dnscheck" "$domain" "$TIMEOUT_BIN" "$BLOCKCHECK_TIMEOUT" "$blockcheck_script" "$report" "$NFQWS_BIN" "$calibration_run_id" "$scan_level" "$blockcheck_pid_file" "$blockcheck_status_file" &
blockcheck_launcher_pid=$!
i=0
while [ ! -s "$blockcheck_pid_file" ] && [ "$i" -lt 10 ]; do
  sleep 1
  i=$((i + 1))
done
blockcheck_pid=$(cat "$blockcheck_pid_file" 2>/dev/null || true)
case "$blockcheck_pid" in
  ""|*[!0-9]*)
    echo "unable to determine isolated calibration process" >&2
    kill "$blockcheck_launcher_pid" 2>/dev/null || true
    wait "$blockcheck_launcher_pid" 2>/dev/null || true
    exit 1
    ;;
esac
blockcheck_pgid=$(proc_pgid "$blockcheck_pid" 2>/dev/null || true)
case "$blockcheck_pgid" in
  ""|0|*[!0-9]*)
    echo "unable to determine calibration process group" >&2
    kill -TERM "$blockcheck_pid" 2>/dev/null || true
    wait "$blockcheck_launcher_pid" 2>/dev/null || true
    exit 1
    ;;
esac
controller_pgid=$(proc_pgid "$$" 2>/dev/null || true)
[ "$blockcheck_pgid" != "$controller_pgid" ] || {
  echo "calibration process group is not isolated from the controller" >&2
  kill -TERM "$blockcheck_pid" 2>/dev/null || true
  wait "$blockcheck_launcher_pid" 2>/dev/null || true
  exit 1
}
blockcheck_start=$(proc_start_time "$blockcheck_pid" 2>/dev/null || true)
blockcheck_exe=$(proc_executable "$blockcheck_pid")
printf '%s|%s|%s|%s|%s\n' "$blockcheck_pid" "$blockcheck_start" "$blockcheck_exe" "$blockcheck_pgid" "$calibration_run_id" > "$process_manifest"
kill -CONT "$blockcheck_pid" 2>/dev/null || {
  echo "unable to resume validated calibration process" >&2
  exit 1
}
wait "$blockcheck_launcher_pid" 2>/dev/null || true
i=0
while [ ! -s "$blockcheck_status_file" ] && [ "$i" -lt 30 ]; do
  process_group_exists "$blockcheck_pgid" || break
  sleep 1
  i=$((i + 1))
done
blockcheck_status=$(cat "$blockcheck_status_file" 2>/dev/null || true)
case "$blockcheck_status" in
  ""|*[!0-9]*)
    echo "calibration process exited without a semantic status" >&2
    exit 1
    ;;
esac
blockcheck_pid=""
set -e
if [ "$blockcheck_status" -ne 0 ]; then
  if [ "$blockcheck_status" -eq 124 ]; then
    echo "upstream blockcheck timed out after ${BLOCKCHECK_TIMEOUT}s; bounded diagnostic tail follows" >&2
  else
    echo "upstream blockcheck failed with exit ${blockcheck_status}; bounded diagnostic tail follows" >&2
  fi
  tail -n 12 "$report" | tr '\r\n\t' '   ' | cut -c1-1024 >&2
  exit "$blockcheck_status"
fi

ROUTER_POLICY_CONFIG="$CONFIG" "$TIMEOUT_BIN" 30 "$ROUTER_POLICY_BIN" zapret-blockcheck-import \
  --report "$report" \
  --binary "$NFQWS_BIN" \
  --provider-version "$provider_version" \
  --queue "$QUEUE_NUM" \
  --domain "$domain" \
  --bundle-id "$bundle_id" \
  --network-fingerprint "$network_fingerprint" \
  --catalog-out "$CATALOG_OUT" \
  --save >"$result"

# The API runner consumes one bounded JSON document. The report itself stays
# private in the run directory and is removed by cleanup.
cat "$result"
