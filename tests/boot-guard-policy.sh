#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-boot-guard-policy-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/state/last-good" "$TMP/runtime"
printf 'verified\n' > "$TMP/state/last-good/manifest.txt"
cat > "$TMP/config.json" <<'EOF'
{
  "openwrt": {
    "direct_mark": "0x41",
    "zapret_mark": "0x42",
    "xray_mark": "0x43",
    "drop_mark": "0x7f"
  }
}
EOF

cat > "$TMP/nft" <<'SH'
#!/bin/sh
set -eu
case "${1:-}" in
  list)
    if [ "${2:-}" = "tables" ]; then
      exit 0
    fi
    if [ "${2:-}" = "table" ] && [ "${3:-}" = "inet" ] && [ "${4:-}" = "router_policy" ]; then
      if [ "${NFT_FOREIGN_CLASSIFIER:-0}" = "1" ]; then
        printf '%s\n' 'table inet router_policy {' '  comment "foreign owner=someone-else"' '}'
        exit 0
      fi
      exit 1
    fi
    exit 1
    ;;
  delete)
    printf '%s\n' "$*" >> "$NFT_COMMAND_LOG"
    exit 0
    ;;
esac
if [ "${1:-}" = "-f" ]; then
  cp "$2" "$BOOT_GUARD_CAPTURE"
fi
exit 0
SH
chmod +x "$TMP/nft"

cat > "$TMP/router-policy" <<'SH'
#!/bin/sh
case "$1" in
  internal-verify-candidate|internal-verify-artifacts)
    exit 0
    ;;
  internal-print-managed-marks)
    printf '%s\n' 'managed_mark=0x41' 'managed_mark_name=direct'
    printf '%s\n' 'managed_mark=0x42' 'managed_mark_name=zapret'
    printf '%s\n' 'managed_mark=0x43' 'managed_mark_name=xray'
    printf '%s\n' 'managed_mark=0x7f' 'managed_mark_name=drop'
    exit 0
    ;;
esac
exit 0
SH
chmod +x "$TMP/router-policy"

ROUTER_POLICY_ADAPTER_LIB_ONLY=1
STATE_DIR="$TMP/state"
RUNTIME_DIR="$TMP/runtime"
ROUTER_POLICY_CONFIG_PATH="$TMP/config.json"
NFT_BIN="$TMP/nft"
ROUTER_POLICY_BIN="$TMP/router-policy"
BOOT_GUARD_CAPTURE="$TMP/captured.nft"
NFT_COMMAND_LOG="$TMP/nft.commands"
: > "$NFT_COMMAND_LOG"
export ROUTER_POLICY_ADAPTER_LIB_ONLY STATE_DIR RUNTIME_DIR ROUTER_POLICY_CONFIG_PATH NFT_BIN ROUTER_POLICY_BIN BOOT_GUARD_CAPTURE NFT_COMMAND_LOG
# shellcheck source=openwrt/adapter.sh
. "$ROOT/openwrt/adapter.sh"
install_boot_guard >/dev/null
grep -Fx '    type filter hook forward priority -300; policy accept;' "$BOOT_GUARD_CAPTURE" >/dev/null
if grep -F 'rp boot_guard action=drop_mark' "$BOOT_GUARD_CAPTURE" >/dev/null; then
  echo 'unbound guard unexpectedly emitted a drop mark' >&2
  exit 1
fi
if grep -F 'table inet router_policy {' "$BOOT_GUARD_CAPTURE" >/dev/null; then
  exit 1
fi

printf 'table inet foreign { chain forward { counter accept; } }\n' > "$TMP/unclassified.nft"
if grep -F 'meta mark' "$TMP/unclassified.nft" >/dev/null; then
  exit 1
fi

# A committed, hash-bound last-good bundle is safe to admit before the normal
# reconcile: the classifier and guard are sent in one nft transaction.
mkdir -p "$TMP/state/last-good/generated"
cat > "$TMP/state/last-good/active-transaction.env" <<'EOF'
transaction_id=tx_0123456789abcdef
revision_id=rev_1_0123456789ab
candidate_hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
artifact_manifest_hash=sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
transaction_state=committed
EOF
printf '%s\n' '{ "openwrt": {} }' > "$TMP/state/last-good/router-policy-config.json"
cat > "$TMP/state/last-good/generated/router-policy.nft" <<'EOF'
# generated transaction=tx_0123456789abcdef revision=rev_1_0123456789ab candidate=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
table inet router_policy {
  comment "router-policy owner=flintroute"
  chain rp_prerouting {
    type filter hook prerouting priority mangle; policy accept;
  }
}
EOF
install_boot_guard >/dev/null
grep -F 'table inet router_policy {' "$BOOT_GUARD_CAPTURE" >/dev/null
grep -F 'meta mark 0x41 counter accept comment "rp boot_guard allow=meta"' "$BOOT_GUARD_CAPTURE" >/dev/null
grep -F 'ct mark 0x43 counter accept comment "rp boot_guard allow=conntrack"' "$BOOT_GUARD_CAPTURE" >/dev/null
if grep -F 'meta mark 0x7f counter accept' "$BOOT_GUARD_CAPTURE" >/dev/null; then
  exit 1
fi
classifier_line=$(grep -n '^table inet router_policy {' "$BOOT_GUARD_CAPTURE" | cut -d: -f1)
guard_line=$(grep -n '^table inet router_policy_boot_guard {' "$BOOT_GUARD_CAPTURE" | cut -d: -f1)
[ "$classifier_line" -lt "$guard_line" ] || exit 1

# An existing classifier with no FlintRoute ownership proof is a hard fence:
# do not redeclare or delete it, and do not admit any mark whose producer is
# unknown. Ordinary forwarding remains available; only an explicit drop mark
# is blocked by the guard.
export NFT_FOREIGN_CLASSIFIER=1
install_boot_guard >/dev/null
if grep -F 'table inet router_policy {' "$BOOT_GUARD_CAPTURE" >/dev/null; then
  echo 'foreign classifier was copied into boot guard transition' >&2
  exit 1
fi
if grep -E 'allow=meta|allow=conntrack' "$BOOT_GUARD_CAPTURE" >/dev/null; then
  echo 'foreign classifier caused mark admission' >&2
  exit 1
fi
grep -Fx '    type filter hook forward priority -300; policy accept;' "$BOOT_GUARD_CAPTURE" >/dev/null
grep -F 'rp boot_guard action=drop_mark' "$BOOT_GUARD_CAPTURE" >/dev/null
if grep -F 'delete table inet router_policy' "$NFT_COMMAND_LOG" >/dev/null; then
  echo 'foreign classifier was deleted during boot guard install' >&2
  exit 1
fi
unset NFT_FOREIGN_CLASSIFIER

echo "boot_guard_unclassified_forwarding_preserved=true"
echo "boot_guard_early_classifier_verified=true"
echo "boot_guard_foreign_classifier_fenced=true"
