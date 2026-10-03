#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-boot-guard-baseline-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/state/last-good" "$TMP/runtime"
cat > "$TMP/config.json" <<'EOF'
{}
EOF

cat > "$TMP/nft" <<'SH'
#!/bin/sh
set -eu
case "${1:-}" in
  list)
    [ "${2:-}" = "tables" ] && exit 0
    exit 1
    ;;
  delete) exit 0 ;;
esac
exit 0
SH
chmod +x "$TMP/nft"

cat > "$TMP/router-policy" <<'SH'
#!/bin/sh
set -eu
case "${1:-}" in
  internal-verify-empty-baseline)
    [ "$#" -eq 5 ]
    [ "$2" = --revision ] && [ "$3" = "$revision" ]
    [ "$4" = --candidate-hash ] && [ "$5" = "$recovery_candidate_hash" ]
    exit "${BASELINE_EMPTY_STATUS:-0}"
    ;;
  internal-verify-no-owned-ip-state)
    [ "$#" -eq 1 ]
    exit "${BASELINE_IP_STATUS:-0}"
    ;;
  *) exit 2 ;;
esac
SH
chmod +x "$TMP/router-policy"

ROUTER_POLICY_ADAPTER_LIB_ONLY=1
STATE_DIR="$TMP/state"
RUNTIME_DIR="$TMP/runtime"
ROUTER_POLICY_CONFIG_PATH="$TMP/config.json"
NFT_BIN="$TMP/nft"
ROUTER_POLICY_BIN="$TMP/router-policy"
guard_path="$RUNTIME_DIR/boot-guard.nft"
export ROUTER_POLICY_ADAPTER_LIB_ONLY STATE_DIR RUNTIME_DIR ROUTER_POLICY_CONFIG_PATH NFT_BIN ROUTER_POLICY_BIN
# shellcheck source=openwrt/adapter.sh
. "$ROOT/openwrt/adapter.sh"

txid=baseline
revision=rev_1_001122334455
recovery_candidate_hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export txid revision recovery_candidate_hash

output=$(clear_boot_guard_baseline)
printf '%s\n' "$output" | grep -Fx 'boot_guard=cleared' >/dev/null
printf '%s\n' "$output" | grep -Fx 'operation=clear-boot-guard-baseline' >/dev/null
printf '%s\n' "$output" | grep -Fx "active_revision=$revision" >/dev/null
printf '%s\n' "$output" | grep -Fx "active_candidate_hash=$recovery_candidate_hash" >/dev/null
printf '%s\n' "$output" | grep -Fx 'transaction_state=baseline_confirmed' >/dev/null
printf '%s\n' "$output" | grep -Fx 'route_assignments=absent' >/dev/null

# A failed root-side proof must preserve the guard, not merely print a bound
# success response. This is an adapter fixture, not hardware absence evidence.
for failure in manifest ip_state; do
  printf 'guard-sentinel\n' > "$guard_path"
  if (
    case "$failure" in
      manifest) BASELINE_EMPTY_STATUS=1 clear_boot_guard_baseline ;;
      ip_state) BASELINE_IP_STATUS=1 clear_boot_guard_baseline ;;
    esac
  ) > "$TMP/failed.txt" 2>&1; then
    echo "baseline clear accepted failed root proof: $failure" >&2
    exit 1
  fi
  [ "$(cat "$guard_path")" = guard-sentinel ]
done

echo "baseline_boot_guard_clear_is_bound=true"
echo "baseline_boot_guard_failed_proof_preserves_guard=true"
