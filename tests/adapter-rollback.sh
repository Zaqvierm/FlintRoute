#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-adapter-test-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/state" "$TMP/runtime" "$TMP/etc" "$TMP/xray"

STATE_DIR="$TMP/state"
RUNTIME_DIR="$TMP/runtime"
ROUTER_POLICY_CONFIG_PATH="$TMP/etc/config.json"
if [ -x "$ROOT/dist/router-policy" ]; then
  ROUTER_POLICY_BIN="$ROOT/dist/router-policy"
else
  ROUTER_POLICY_BIN="$ROOT/dist/router-policy.exe"
fi
ROUTER_POLICY_ADAPTER_LIB_ONLY=1
mock_uci() {
  if [ "${1:-}" = "-q" ] && [ "${2:-}" = "get" ]; then
    if [ "${3:-}" = "dhcp.@dnsmasq[0].confdir" ] && [ -n "${MOCK_DNSMASQ_CONFDIR:-}" ]; then
      printf '%s\n' "$MOCK_DNSMASQ_CONFDIR"
      return 0
    fi
    return 1
  fi
  return 0
}
# The adapter library is sourced below and consumes this command name through
# its own globals; ShellCheck cannot infer that cross-file read.
# shellcheck disable=SC2034
UCI_BIN=mock_uci
export STATE_DIR RUNTIME_DIR ROUTER_POLICY_CONFIG_PATH ROUTER_POLICY_BIN ROUTER_POLICY_ADAPTER_LIB_ONLY
# shellcheck source=openwrt/adapter.sh
. "$ROOT/openwrt/adapter.sh"

# Keep the transaction root explicit for the fixture as it is initialized by
# the sourced adapter rather than assigned in this test file.
txroot="$STATE_DIR/transactions"

config="$TMP/etc/config.json"
active_nft="$TMP/etc/router-policy.nft"
active_dnsmasq="$TMP/etc/router-policy-dnsmasq.conf"
active_xray="$TMP/xray/active.json"
MOCK_DNSMASQ_CONFDIR="$TMP/not-loaded"
if verify_dnsmasq_include_target >/dev/null 2>&1; then
  echo "dnsmasq include outside the configured confdir was accepted" >&2
  exit 1
fi
MOCK_DNSMASQ_CONFDIR="${active_dnsmasq%/*}"
verify_dnsmasq_include_target
printf 'config-old\n' > "$config"
printf 'nft-old\n' > "$active_nft"
printf 'dns-old\n' > "$active_dnsmasq"
printf 'xray-old\n' > "$active_xray"

snapshot="$TMP/snapshot"
create_snapshot "$snapshot"
printf 'corrupt\n' >> "$snapshot/xray-active.json"
printf 'config-new\n' > "$config"
if restore_snapshot "$snapshot" >/dev/null 2>&1; then
  echo "corrupted snapshot was restored" >&2
  exit 1
fi
[ "$(cat "$config")" = "config-new" ] || { echo "restore modified files before hash verification" >&2; exit 1; }

# Snapshot verification must precede stopping any owned Zapret profile.  A
# corrupt snapshot must be a read-only failure and must not leave the live
# profile stopped merely because restore was attempted.
PROFILE_ROOT="$TMP/profile-config"
PROFILE_INIT_ROOT="$TMP/profile-init"
PROFILE_STOP_LOG="$TMP/profile-stop.log"
mkdir -p "$PROFILE_ROOT" "$PROFILE_INIT_ROOT"
printf 'profile-config\n' > "$PROFILE_ROOT/test-profile.conf"
cat > "$PROFILE_INIT_ROOT/router-policy-zapret-test-profile" <<'SH'
#!/bin/sh
case "${1:-}" in
  running) exit 0 ;;
  stop) printf 'stop\n' >> "$PROFILE_STOP_LOG"; exit 0 ;;
  *) exit 0 ;;
esac
SH
chmod +x "$PROFILE_INIT_ROOT/router-policy-zapret-test-profile"
export PROFILE_STOP_LOG
zapret_profile_dir="$PROFILE_ROOT"
zapret_profile_init_prefix="$PROFILE_INIT_ROOT/router-policy-zapret-"
active_zapret_profiles="$TMP/profiles.manifest"
printf 'test-profile|%s|%s|205|\n' \
  "$PROFILE_ROOT/test-profile.conf" \
  "$PROFILE_INIT_ROOT/router-policy-zapret-test-profile" > "$active_zapret_profiles"
profile_snapshot="$TMP/profile-snapshot"
create_snapshot "$profile_snapshot"
printf 'corrupt\n' >> "$profile_snapshot/xray-active.json"
if restore_snapshot "$profile_snapshot" >/dev/null 2>&1; then
  echo "corrupted profile snapshot was restored" >&2
  exit 1
fi
[ ! -e "$PROFILE_STOP_LOG" ] || { echo "profile service was stopped before snapshot verification" >&2; exit 1; }
active_zapret_profiles="$TMP/no-profile-manifest"
# shellcheck disable=SC2034 # consumed by the sourced adapter library
zapret_profile_dir="${active_zapret_profiles%/*}/profiles"
# shellcheck disable=SC2034 # consumed by the sourced adapter library
zapret_profile_init_prefix="/etc/init.d/router-policy-zapret-"

printf 'config-old\n' > "$config"
printf 'dns-old\n' > "$active_dnsmasq"
printf 'xray-old\n' > "$active_xray"
rm -f "$active_nft"
create_snapshot "$snapshot"
printf 'project-created\n' > "$active_nft"
printf 'xray-new\n' > "$active_xray"
restore_snapshot "$snapshot"
[ ! -e "$active_nft" ] || { echo "owned absent marker did not remove project file" >&2; exit 1; }
[ "$(cat "$active_xray")" = "xray-old" ] || { echo "Xray config was not restored" >&2; exit 1; }

outside="$TMP/outside"
printf 'keep\n' > "$outside"
printf '%s|absent|evil|0|-|project\n' "$outside" >> "$snapshot/manifest.txt"
printf '%s\n' "$outside" > "$snapshot/evil.absent"
sha_file "$snapshot/manifest.txt" > "$snapshot/manifest.sha256"
if restore_snapshot "$snapshot" >/dev/null 2>&1; then
  echo "unowned absent marker was accepted" >&2
  exit 1
fi
[ "$(cat "$outside")" = "keep" ] || { echo "unowned file was deleted" >&2; exit 1; }

txid="tx_0011223344556677"
revision="rev_2_001122334455"
txdir="$txroot/$revision/$txid"
mkdir -p "$txdir"
good_token="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
token_hash="sha256:$(printf '%s' "$good_token" | sha256sum | awk '{print $1}')"
binding_file="$txdir/binding.env"
capability_file="$txdir/rollback.cap"
{
  echo "transaction_id=$txid"
  echo "revision_id=$revision"
  echo "candidate_hash=sha256:candidate"
  echo "artifact_manifest_hash=sha256:manifest"
  echo "artifacts_ready=true"
  echo "artifact_block_reason="
  echo "artifacts_simulation=false"
  echo "rollback_token_hash=$token_hash"
} > "$binding_file"
printf '%s\n' "$good_token" > "$capability_file"
chmod 600 "$capability_file"
verify_token
printf '%s\n' "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" > "$capability_file"
chmod 600 "$capability_file"
if verify_token >/dev/null 2>&1; then
  echo "wrong rollback token was accepted" >&2
  exit 1
fi

echo "adapter_rollback_integrity_ok=true"
