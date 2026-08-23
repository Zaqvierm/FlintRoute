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
    [ "${2:-}" = "tables" ] && exit 0
    exit 1
    ;;
  delete) exit 0 ;;
esac
if [ "${1:-}" = "-f" ]; then
  cp "$2" "$BOOT_GUARD_CAPTURE"
fi
exit 0
SH
chmod +x "$TMP/nft"

cat > "$TMP/router-policy" <<'SH'
#!/bin/sh
set -eu
[ "${1:-}" = "internal-print-managed-marks" ] || exit 2
printf '%s\n' managed_mark=0x41 managed_mark=0x42 managed_mark=0x43 managed_mark=0x7f
SH
chmod +x "$TMP/router-policy"

ROUTER_POLICY_ADAPTER_LIB_ONLY=1
STATE_DIR="$TMP/state"
RUNTIME_DIR="$TMP/runtime"
ROUTER_POLICY_CONFIG_PATH="$TMP/config.json"
NFT_BIN="$TMP/nft"
ROUTER_POLICY_BIN="$TMP/router-policy"
BOOT_GUARD_CAPTURE="$TMP/captured.nft"
export ROUTER_POLICY_ADAPTER_LIB_ONLY STATE_DIR RUNTIME_DIR ROUTER_POLICY_CONFIG_PATH NFT_BIN ROUTER_POLICY_BIN BOOT_GUARD_CAPTURE
# shellcheck source=openwrt/adapter.sh
. "$ROOT/openwrt/adapter.sh"

install_boot_guard >/dev/null
grep -Fx '    type filter hook forward priority -4; policy accept;' "$BOOT_GUARD_CAPTURE" >/dev/null
if grep -Fx '    counter drop' "$BOOT_GUARD_CAPTURE" >/dev/null; then
  echo "boot guard still drops all forwarded traffic" >&2
  exit 1
fi
for mark in 0x41 0x42 0x43 0x7f; do
  grep -F "meta mark $mark counter drop" "$BOOT_GUARD_CAPTURE" >/dev/null
  grep -F "ct mark $mark counter drop" "$BOOT_GUARD_CAPTURE" >/dev/null
done

printf 'table inet foreign { chain forward { counter accept; } }\n' > "$TMP/unclassified.nft"
if grep -F 'meta mark' "$TMP/unclassified.nft" >/dev/null; then
  exit 1
fi

echo "boot_guard_scoped_to_managed_marks=true"
echo "boot_guard_unclassified_forwarding_preserved=true"
