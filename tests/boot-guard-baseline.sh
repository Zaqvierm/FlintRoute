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

ROUTER_POLICY_ADAPTER_LIB_ONLY=1
STATE_DIR="$TMP/state"
RUNTIME_DIR="$TMP/runtime"
ROUTER_POLICY_CONFIG_PATH="$TMP/config.json"
NFT_BIN="$TMP/nft"
export ROUTER_POLICY_ADAPTER_LIB_ONLY STATE_DIR RUNTIME_DIR ROUTER_POLICY_CONFIG_PATH NFT_BIN
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

echo "baseline_boot_guard_clear_is_bound=true"
