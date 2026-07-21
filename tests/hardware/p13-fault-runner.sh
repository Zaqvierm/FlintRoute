#!/bin/sh
set -eu

run_dir="${1:-}"
case "$run_dir" in
  /tmp/flintroute-p13/p13-fault-*) ;;
  *) echo "unsafe run directory" >&2; exit 64 ;;
esac

mkdir -p "$run_dir"
chmod 700 "$run_dir"
export ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json

wait_running() {
  service="$1"
  executable="$2"
  attempts=0
  while [ "$attempts" -lt 90 ]; do
    if "/etc/init.d/$service" running >/dev/null 2>&1 && managed_pid "$service" "$executable" >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  return 1
}

managed_pid() {
  service="$1"
  executable="$2"
  command -v jq >/dev/null 2>&1 || return 1
  pids="$(ubus call service list "{\"name\":\"$service\"}" | jq -r --arg service "$service" --arg executable "$executable" '
    .[$service].instances // {} |
    to_entries[] |
    select(.value.running == true) |
    select(.value.command[0] == $executable) |
    .value.pid
  ')"
  [ -n "$pids" ] || return 1
  [ "$(printf '%s\n' "$pids" | wc -l)" -eq 1 ] || return 1
  [ -e "/proc/$pids/exe" ] || return 1
  [ "$(readlink -f "/proc/$pids/exe")" = "$executable" ] || return 1
  printf '%s\n' "$pids"
}

restart_probe() {
  service="$1"
  executable="$2"
  label="$3"
  route="$4"
  domain="$5"
  bundle="$6"
  before="$(managed_pid "$service" "$executable" 2>/dev/null || true)"
  if [ -z "$before" ]; then
    printf '{"case":"%s","status":"FAIL","reason":"process_missing_before_kill"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  if ! kill -KILL "$before"; then
    printf '{"case":"%s","status":"FAIL","reason":"kill_failed"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  if ! wait_running "$service" "$executable"; then
    printf '{"case":"%s","status":"FAIL","reason":"respawn_timeout"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  after="$(managed_pid "$service" "$executable" 2>/dev/null || true)"
  if [ -z "$after" ] || [ "$after" = "$before" ]; then
    printf '{"case":"%s","status":"FAIL","reason":"process_missing_after_respawn"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  if ! /usr/bin/router-policy probe-route --no-persist --route "$route" "$domain" "$bundle" >"$run_dir/$label.json"; then
    printf '{"case":"%s","status":"FAIL","reason":"route_probe_failed"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  printf '{"case":"%s","status":"PASS","sigkill_delivered":true,"service_recovered":true}\n' "$label" >>"$run_dir/failure-injections.jsonl"
}

wait_running router-policy /usr/bin/router-policy
sha256sum /etc/router-policy/config/default.json /etc/router-policy/zapret/nfqws.conf >"$run_dir/pre-fault-artifacts.sha256"
sha256sum /etc/router-policy/state/router-policy.bbolt >"$run_dir/pre-fault-state.sha256"
cp /tmp/router-policy/active-transaction.env "$run_dir/pre-fault-binding.env"
/usr/bin/router-policy status >"$run_dir/pre-fault-status.json"

restart_probe router-policy-zapret /usr/bin/nfqws kill-nfqws zapret discord.com discord_acceptance
restart_probe router-policy-xray /usr/bin/xray kill-xray proxy-4 chatgpt.com chatgpt
restart_probe router-policy /usr/bin/router-policy kill-controller direct github.com github

/usr/bin/router-policy probe-route --no-persist --route drop example.invalid github >"$run_dir/drop-after-faults.json"
sha256sum /etc/router-policy/config/default.json /etc/router-policy/zapret/nfqws.conf >"$run_dir/post-fault-artifacts.sha256"
sha256sum /etc/router-policy/state/router-policy.bbolt >"$run_dir/post-fault-state.sha256"
cp /tmp/router-policy/active-transaction.env "$run_dir/post-fault-binding.env"
/usr/bin/router-policy status >"$run_dir/post-fault-status.json"

if ! cmp -s "$run_dir/pre-fault-artifacts.sha256" "$run_dir/post-fault-artifacts.sha256" ||
  ! cmp -s "$run_dir/pre-fault-binding.env" "$run_dir/post-fault-binding.env"; then
  echo "committed artifact binding changed during process restart tests" >&2
  exit 1
fi
