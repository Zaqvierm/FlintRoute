#!/bin/sh
set -eu
umask 077

mode="${1:-}"
run_id="${2:-}"
case "$run_id" in
  p13-state-[a-z0-9._-]*) ;;
  *) echo "unsafe state-corruption run ID" >&2; exit 64 ;;
esac

state=/etc/router-policy/state/router-policy.bbolt
config=/etc/router-policy/config/default.json
binding=/tmp/router-policy/active-transaction.env
controller=/etc/init.d/router-policy
watchdog=/etc/init.d/router-policy-watchdog
xray=/etc/init.d/router-policy-xray
zapret=/etc/init.d/router-policy-zapret
recovery=/etc/router-policy/state/recovery-tests/$run_id
backup=$recovery/router-policy.bbolt.verified
run_dir=/tmp/flintroute-p13/$run_id
result=$run_dir/state-corruption.env
marker=$recovery/rescue.env

wait_health() {
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    if curl -fsS http://127.0.0.1:8787/api/v1/health >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  return 1
}

if [ "$mode" = rescue ]; then
  expected_hash="${3:-}"
  sleep 15
  "$watchdog" stop >/dev/null 2>&1 || true
  "$controller" stop >/dev/null 2>&1 || true
  sleep 1
  cp "$backup" "$state.restore"
  chmod 600 "$state.restore"
  /usr/bin/router-policy internal-verify-state-backup --path "$state.restore" >/dev/null
  restored_hash=$(sha256sum "$state.restore" | awk '{print $1}')
  [ "$restored_hash" = "$expected_hash" ]
  mv "$state.restore" "$state"
  "$controller" start >/dev/null
  "$watchdog" start >/dev/null
  if wait_health; then
    {
      echo rescue=PASS
      echo restored_hash="$restored_hash"
    } >"$marker"
    exit 0
  fi
  echo rescue=FAIL >"$marker"
  exit 1
fi

[ "$mode" = run ] || { echo "usage: runner run|rescue RUN_ID" >&2; exit 64; }
[ -d "$run_dir" ] && [ -s "$state" ] && [ -s "$config" ] && [ -s "$binding" ]
mkdir -p "$recovery"
chmod 700 "$recovery"
pre_config_hash=$(sha256sum "$config" | awk '{print $1}')
pre_binding_hash=$(sha256sum "$binding" | awk '{print $1}')

"$watchdog" stop >/dev/null 2>&1 || true
"$controller" stop >/dev/null 2>&1 || true
sleep 1
cp "$state" "$backup.tmp"
chmod 600 "$backup.tmp"
/usr/bin/router-policy internal-verify-state-backup --path "$backup.tmp" >/dev/null
mv "$backup.tmp" "$backup"
backup_hash=$(sha256sum "$backup" | awk '{print $1}')

sh "$0" rescue "$run_id" "$backup_hash" >"$recovery/rescue.log" 2>&1 </dev/null &
rescue_pid=$!
echo "$rescue_pid" >"$recovery/rescue.pid"

dd if=/dev/zero of="$state" bs=4096 count=1 conv=notrunc >/dev/null 2>&1
"$controller" start >/dev/null 2>&1 || true
sleep 5
if curl -fsS http://127.0.0.1:8787/api/v1/health >/dev/null 2>&1; then
  corruption_detected=false
else
  corruption_detected=true
fi

tables_intact=true
for table in 100 101 102; do
  [ "$(ip -4 route show table "$table" | wc -l)" -gt 0 ] || tables_intact=false
  [ "$(ip -6 route show table "$table" | wc -l)" -gt 0 ] || tables_intact=false
done
"$xray" running >/dev/null 2>&1 || tables_intact=false
"$zapret" running >/dev/null 2>&1 || tables_intact=false

attempts=0
while [ ! -s "$marker" ] && [ "$attempts" -lt 60 ]; do
  attempts=$((attempts + 1))
  sleep 1
done
[ -s "$marker" ]
rescue_status=$(sed -n 's/^rescue=//p' "$marker" | head -n1)
restored_hash=$(sed -n 's/^restored_hash=//p' "$marker" | head -n1)
[ "$rescue_status" = PASS ]
[ "$restored_hash" = "$backup_hash" ]
wait_health
"$watchdog" running >/dev/null
"$watchdog" enabled >/dev/null
post_config_hash=$(sha256sum "$config" | awk '{print $1}')
post_binding_hash=$(sha256sum "$binding" | awk '{print $1}')
[ "$pre_config_hash" = "$post_config_hash" ]
[ "$pre_binding_hash" = "$post_binding_hash" ]
[ "$corruption_detected" = true ]
[ "$tables_intact" = true ]

{
  echo run_id="$run_id"
  echo checked_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo corruption_detected=true
  echo committed_dataplane_survived=true
  echo rescue=PASS
  echo config_digest_restored=true
  echo binding_digest_restored=true
  echo backup_sha256="$backup_hash"
} >"$result"
chmod 600 "$result"
echo state_corruption_recovery=PASS
