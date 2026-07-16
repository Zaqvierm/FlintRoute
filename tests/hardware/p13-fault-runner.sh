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
  process="$2"
  attempts=0
  while [ "$attempts" -lt 90 ]; do
    if "/etc/init.d/$service" running >/dev/null 2>&1 && pidof "$process" >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  return 1
}

restart_probe() {
  service="$1"
  process="$2"
  label="$3"
  route="$4"
  domain="$5"
  bundle="$6"
  before="$(pidof "$process" 2>/dev/null || true)"
  if [ -z "$before" ]; then
    printf '{"case":"%s","status":"FAIL","reason":"process_missing_before_kill"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  for pid in $before; do
    if ! kill -KILL "$pid"; then
      printf '{"case":"%s","status":"FAIL","reason":"kill_failed"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
      return 1
    fi
  done
  if ! wait_running "$service" "$process"; then
    printf '{"case":"%s","status":"FAIL","reason":"respawn_timeout"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  after="$(pidof "$process" 2>/dev/null || true)"
  if [ -z "$after" ]; then
    printf '{"case":"%s","status":"FAIL","reason":"process_missing_after_respawn"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  if ! /usr/bin/router-policy probe-route --no-persist --route "$route" "$domain" "$bundle" >"$run_dir/$label.json"; then
    printf '{"case":"%s","status":"FAIL","reason":"route_probe_failed"}\n' "$label" >>"$run_dir/failure-injections.jsonl"
    return 1
  fi
  printf '{"case":"%s","status":"PASS","sigkill_delivered":true,"service_recovered":true}\n' "$label" >>"$run_dir/failure-injections.jsonl"
}

/etc/init.d/router-policy restart
wait_running router-policy router-policy
sha256sum /etc/router-policy/config/default.json /etc/router-policy/zapret/nfqws.conf >"$run_dir/pre-fault-artifacts.sha256"
sha256sum /etc/router-policy/state/router-policy.bbolt >"$run_dir/pre-fault-state.sha256"
cp /tmp/router-policy/active-transaction.env "$run_dir/pre-fault-binding.env"
/usr/bin/router-policy status >"$run_dir/pre-fault-status.json"

restart_probe router-policy-zapret nfqws kill-nfqws zapret discord.com discord_acceptance
restart_probe router-policy-xray xray kill-xray proxy-4 chatgpt.com chatgpt
restart_probe router-policy router-policy kill-controller direct github.com github

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
