#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
# Use a fresh temp directory that does not inherit a polluted TMPDIR from a previous run.
_TMPBASE="/tmp"
if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
  _TMPBASE="$TMPDIR"
fi
TMP="$_TMPBASE/router-policy-openwrt-integration-$$"
# Ensure Go uses a valid temp directory even if TMPDIR was polluted by a prior run.
if command -v cygpath >/dev/null 2>&1; then
  export GOTMPDIR="${GOTMPDIR:-$(cygpath -m /tmp)}"
else
  export GOTMPDIR="${GOTMPDIR:-/tmp}"
fi
mkdir -p "$GOTMPDIR"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/state/diagnostics" "$TMP/runtime" "$TMP/etc" "$TMP/xray" "$TMP/bin"

# Convert a POSIX path to a native Windows path when running under MSYS/Git Bash.
# Node.js on Windows does not understand /h/LAN/... style paths.
to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

if command -v cygpath >/dev/null 2>&1; then
  TMP_NATIVE=$(cygpath -m "$TMP")
  ROOT_NATIVE=$(cygpath -m "$ROOT")
  EXE=.exe
  GO="${GO:-$ROOT_NATIVE/.tools/go1.26.5/go/bin/go.exe}"
  ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-$ROOT_NATIVE/dist/router-policy.exe}"
else
  TMP_NATIVE="$TMP"
  ROOT_NATIVE="$ROOT"
  EXE=
  GO="${GO:-$ROOT/.tools/go1.26.5/go/bin/go}"
  ROUTER_POLICY_BIN="${ROUTER_POLICY_BIN:-$ROOT/dist/router-policy}"
fi
STATE_DIR="$TMP_NATIVE/state"
RUNTIME_DIR="$TMP_NATIVE/runtime"
ROUTER_POLICY_CONFIG_PATH="$TMP_NATIVE/etc/config.json"
ACTIVE_NFT="$TMP_NATIVE/etc/router-policy.nft"
ACTIVE_DNSMASQ="$TMP_NATIVE/etc/router-policy-dnsmasq.conf"
ACTIVE_XRAY="$TMP_NATIVE/xray/active.json"
ACTIVE_ZAPRET="$TMP_NATIVE/etc/nfqws.conf"
ROUTER_POLICY_ADAPTER_SELF="$ROOT/openwrt/adapter.sh"
MOCK_OPENWRT_LOG="$TMP_NATIVE/openwrt-calls.log"

(cd "$ROOT" && "$GO" build -o "$TMP_NATIVE/bin/mock-openwrt$EXE" ./tests/mock-openwrt-command) || {
  echo "failed to build mock-openwrt" >&2
  exit 1
}
[ -f "$TMP_NATIVE/bin/mock-openwrt$EXE" ] || {
  echo "mock-openwrt binary not found after build" >&2
  exit 1
}
for command_name in nft fw4 dnsmasq dnsmasq-init xray xray-init nfqws zapret-init ip uci wget nslookup pidof; do
  cp "$TMP/bin/mock-openwrt$EXE" "$TMP/bin/$command_name$EXE"
done

NFT_BIN="$TMP_NATIVE/bin/nft$EXE"
FW4_BIN="$TMP_NATIVE/bin/fw4$EXE"
DNSMASQ_BIN="$TMP_NATIVE/bin/dnsmasq$EXE"
DNSMASQ_INIT="$TMP_NATIVE/bin/dnsmasq-init$EXE"
XRAY_BIN="$TMP_NATIVE/bin/xray$EXE"
XRAY_INIT="$TMP_NATIVE/bin/xray-init$EXE"
NFQWS_BIN="$TMP_NATIVE/bin/nfqws$EXE"
ZAPRET_INIT="$TMP_NATIVE/bin/zapret-init$EXE"
IP_BIN="$TMP_NATIVE/bin/ip$EXE"
UCI_BIN="$TMP_NATIVE/bin/uci$EXE"
WGET_BIN="$TMP_NATIVE/bin/wget$EXE"
NSLOOKUP_BIN="$TMP_NATIVE/bin/nslookup$EXE"
PIDOF_BIN="$TMP_NATIVE/bin/pidof$EXE"
ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS=1
ROUTER_POLICY_AUTO_COLLECT_EVIDENCE=0
MOCK_UCI_STATE="$TMP_NATIVE/uci-state.env"
MOCK_IP_STATE="$TMP_NATIVE/ip-state.json"
MOCK_SERVICE_STATE="$TMP_NATIVE/service-state"
export STATE_DIR RUNTIME_DIR ROUTER_POLICY_CONFIG_PATH ROUTER_POLICY_BIN ROUTER_POLICY_ADAPTER_SELF
export ACTIVE_NFT ACTIVE_DNSMASQ ACTIVE_XRAY ACTIVE_ZAPRET MOCK_OPENWRT_LOG
export NFT_BIN FW4_BIN DNSMASQ_BIN DNSMASQ_INIT XRAY_BIN XRAY_INIT NFQWS_BIN ZAPRET_INIT IP_BIN UCI_BIN WGET_BIN NSLOOKUP_BIN PIDOF_BIN
export ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS ROUTER_POLICY_AUTO_COLLECT_EVIDENCE MOCK_UCI_STATE MOCK_IP_STATE MOCK_SERVICE_STATE

printf '%s\n' \
  'firewall.@defaults[0].flow_offloading=1' \
  'firewall.@defaults[0].flow_offloading_hw=1' > "$TMP/uci-state.env"

rm -f "$MOCK_IP_STATE"
printf 'lan_management_path=true\nglinet_uhttpd_path=true\n' > "$TMP/state/diagnostics/management.env"
cat > "$TMP/state/diagnostics/network.json" <<'JSON'
{
  "status": "VERIFIED",
  "source": "local-shell-integration-fixture",
  "simulation": true,
  "wan_interface": "wan",
  "lan_interfaces": ["br-lan"],
  "ipv4_gateway": "192.0.2.1",
  "ipv6_gateway": "2001:db8::1",
  "ipv6_available": true,
  "transparent_proxy_mode": "tproxy",
  "flow_offloading_status": "VERIFIED",
  "software_flow_offloading": true,
  "hardware_flow_offloading": true,
  "collected_at": "2026-07-12T00:00:00Z",
  "expires_at": "2999-01-01T00:00:00Z"
}
JSON

adapter() {
  "$ROOT/openwrt/adapter.sh" "$@"
}

json_field() {
  node -e 'const fs=require("fs"); const value=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(String(value[process.argv[2]] ?? ""));' "$(to_native_path "$1")" "$2"
}

hash_token() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print "sha256:" $1}'
  else
    printf '%s' "$1" | openssl dgst -sha256 | awk '{print "sha256:" $NF}'
  fi
}

setup_transaction() {
  txid="$1"
  revision="$2"
  token="$3"
  mode="${4:-direct}"
  txdir="$STATE_DIR/transactions/$revision/$txid"
  mkdir -p "$txdir"
  cp "$ROOT/config/default.json" "$txdir/candidate.json"
  node -e 'const fs=require("fs"); const path=process.argv[1]; const state=process.argv[2]; const runtime=process.argv[3]; const mode=process.argv[4]; const config=JSON.parse(fs.readFileSync(path, "utf8")); config.storage.state_dir=state; config.storage.runtime_dir=runtime; config.storage.database=state+"/router-policy.bbolt"; config.openwrt.flow_offloading_policy="disable"; if(mode==="zapret"){const route=config.routes.find((item)=>item.type==="zapret"); route.disabled=false; route.status="CONFIGURED"; config.services.zapret_acceptance={category:"TSPU_RESTRICTED",domains:["blocked.example"],allowed_paths:["zapret","drop"],forbidden_paths:[],require_non_ru_egress:false,probe_urls:[{name:"web",url:"https://blocked.example/",required:true,expected_codes:[200],body_mode:"optional"}]};} fs.writeFileSync(path, JSON.stringify(config, null, 2)+"\n");' "$(to_native_path "$txdir/candidate.json")" "$(to_native_path "$STATE_DIR")" "$(to_native_path "$RUNTIME_DIR")" "$mode"
  (cd "$ROOT" && "$ROUTER_POLICY_BIN" internal-generate-artifacts \
    --candidate "$txdir/candidate.json" \
    --root "$txdir/generated" \
    --transaction "$txid" \
    --revision "$revision" > "$txdir/generated-hashes.json" 2>"$txdir/generr.txt") || {
    echo "internal-generate-artifacts failed:" >&2
    cat "$txdir/generr.txt" >&2
    exit 1
  }
  candidate_hash=$(json_field "$txdir/generated-hashes.json" candidate_hash)
  artifact_manifest_hash=$(json_field "$txdir/generated-hashes.json" artifact_manifest_hash)
  deployment_ready=$(json_field "$txdir/generated-hashes.json" deployment_ready)
  artifact_block_reason=$(json_field "$txdir/generated-hashes.json" block_reason)
  artifacts_simulation=$(json_field "$txdir/generated-hashes.json" simulation)
  token_hash=$(hash_token "$token")
  {
    echo "transaction_id=$txid"
    echo "revision_id=$revision"
    echo "candidate_hash=$candidate_hash"
    echo "artifact_manifest_hash=$artifact_manifest_hash"
    echo "artifacts_ready=$deployment_ready"
    echo "artifact_block_reason=$artifact_block_reason"
    echo "artifacts_simulation=$artifacts_simulation"
    echo "rollback_token_hash=$token_hash"
  } > "$txdir/binding.env"
  printf '%s\n' "$token" > "$txdir/rollback.cap"
  chmod 600 "$txdir/rollback.cap"
}

assert_status() {
  expected="$1"
  actual=$(sed -n 's/^status=//p' "$txdir/status.env")
  [ "$actual" = "$expected" ] || {
    echo "expected transaction status $expected, got $actual" >&2
    exit 1
  }
  printf '%s -> %s\n' "$revision" "$actual" >> "$TMP/state-transitions.log"
}

assert_order() {
  first=$(grep -n "$1" "$TMP/openwrt-calls.log" | head -n 1 | cut -d: -f1)
  second=$(grep -n "$2" "$TMP/openwrt-calls.log" | head -n 1 | cut -d: -f1)
  [ -n "$first" ] && [ -n "$second" ] && [ "$first" -lt "$second" ] || {
    echo "mock command order is wrong: $1 must precede $2" >&2
    exit 1
  }
}

# Successful transaction: generated artifacts are the exact files installed and committed.
printf 'old-config\n' > "$ROUTER_POLICY_CONFIG_PATH"
printf 'old-nft\n' > "$ACTIVE_NFT"
printf 'old-dnsmasq\n' > "$ACTIVE_DNSMASQ"
printf 'old-xray\n' > "$ACTIVE_XRAY"
: > "$TMP/openwrt-calls.log"

setup_transaction "tx_0011223344556677" "rev_2_001122334455" "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status prepared
adapter validate-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status candidate_validated
adapter snapshot-current "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status snapshotted
node "$(to_native_path "$ROOT/tests/build-data-plane-evidence.mjs")" "$(to_native_path "$txdir/generated/verification-plan.json")" "$artifact_manifest_hash" "$(to_native_path "$txdir/data-plane-evidence.json")"
adapter apply-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status applied
adapter verify-management "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status management_verified
adapter verify-data-plane "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status data_plane_verified
adapter commit "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status committed

cmp "$txdir/candidate.json" "$ROUTER_POLICY_CONFIG_PATH"
cmp "$txdir/generated/router-policy.nft" "$ACTIVE_NFT"
cmp "$txdir/generated/router-policy-dnsmasq.conf" "$ACTIVE_DNSMASQ"
cmp "$txdir/generated/xray.json" "$ACTIVE_XRAY"
grep -Fx "candidate_hash=$candidate_hash" "$STATE_DIR/last-good/transaction.env" >/dev/null
grep -Fx "artifact_manifest_hash=$artifact_manifest_hash" "$STATE_DIR/last-good/transaction.env" >/dev/null
grep -Fx "transaction_state=committed" "$RUNTIME_DIR/active-transaction.env" >/dev/null
[ -s "$STATE_DIR/last-good/generated/ip-plan.json" ] || { echo "committed recovery IP plan is missing" >&2; exit 1; }
grep -Fx 'firewall.@defaults[0].flow_offloading=0' "$TMP/uci-state.env" >/dev/null
grep -Fx 'firewall.@defaults[0].flow_offloading_hw=0' "$TMP/uci-state.env" >/dev/null
[ ! -e "$txdir/rollback.cap" ] || { echo "committed capability was not retired" >&2; exit 1; }

assert_order '^nft -c -f ' '^fw4 reload$'
assert_order '^nft delete table inet router_policy$' '^fw4 reload$'
assert_order '^fw4 reload$' "^nft -f $ACTIVE_NFT$"
assert_order '^uci set firewall.@defaults\[0\].flow_offloading=0$' '^ip -4 route replace '
assert_order '^uci commit firewall$' '^fw4 reload$'
assert_order '^dnsmasq-init restart$' '^nslookup localhost 127.0.0.1$'
assert_order '^ip -4 route replace ' '^ip -4 rule del '
assert_order '^ip -6 route replace ' '^ip -6 rule del '
assert_order '^ip -4 rule del ' '^fw4 reload$'
grep -Eq '^ip -4 rule del priority [0-9]+$' "$TMP/openwrt-calls.log" || {
  echo "apply did not replace the project-owned IPv4 priority" >&2
  exit 1
}
grep -q 'rule replace' "$TMP/openwrt-calls.log" && {
  echo "unsupported ip rule replace reached the OpenWrt command log" >&2
  exit 1
}
assert_order '^fw4 reload$' '^dnsmasq-init restart$'
assert_order '^pidof router-policy$' '^wget '

# Firewall/dnsmasq/Xray/IP damage is reconciled from the hash-verified, revision-bound last-good snapshot.
printf 'damaged-nft\n' > "$ACTIVE_NFT"
printf 'damaged-dnsmasq\n' > "$ACTIVE_DNSMASQ"
printf 'damaged-xray\n' > "$ACTIVE_XRAY"
printf '%s\n' \
  'firewall.@defaults[0].flow_offloading=1' \
  'firewall.@defaults[0].flow_offloading_hw=1' > "$TMP/uci-state.env"
xray_restarts_before=$(grep -c '^xray-init restart$' "$TMP/openwrt-calls.log" || true)
rm -f "$MOCK_IP_STATE"
: > "$TMP/openwrt-calls.log"
set +e
wrong_reconcile=$(adapter reconcile "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$artifact_manifest_hash" 2>&1)
wrong_reconcile_rc=$?
set -e
[ "$wrong_reconcile_rc" -ne 0 ] || { echo "reconcile accepted the wrong committed candidate hash" >&2; exit 1; }
printf '%s\n' "$wrong_reconcile" | grep -F 'reason=recovery_binding_mismatch' >/dev/null
grep -F "nft -f $RUNTIME_DIR/boot-guard.nft" "$TMP/openwrt-calls.log" >/dev/null || {
  echo "reconcile failure did not arm the forwarding boot guard" >&2
  exit 1
}

: > "$TMP/openwrt-calls.log"
reconcile_result=$(adapter reconcile "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" "$candidate_hash" "$artifact_manifest_hash")
printf '%s\n' "$reconcile_result" | grep -F 'reconcile=ok' >/dev/null
cmp "$txdir/generated/router-policy.nft" "$ACTIVE_NFT"
cmp "$txdir/generated/router-policy-dnsmasq.conf" "$ACTIVE_DNSMASQ"
cmp "$txdir/generated/xray.json" "$ACTIVE_XRAY"
grep -Fx 'firewall.@defaults[0].flow_offloading=0' "$TMP/uci-state.env" >/dev/null
grep -Fx 'firewall.@defaults[0].flow_offloading_hw=0' "$TMP/uci-state.env" >/dev/null
[ -s "$MOCK_IP_STATE" ] || { echo "reconcile did not restore committed IP routes/rules" >&2; exit 1; }
assert_order "^nft -f $RUNTIME_DIR/boot-guard.nft$" '^xray-init stop$'
assert_order '^xray-init stop$' '^ip -4 route replace '
assert_order '^ip -4 rule del ' '^fw4 reload$'
assert_order '^fw4 reload$' '^dnsmasq-init restart$'
[ "$(grep -c '^nft delete table inet router_policy_boot_guard$' "$TMP/openwrt-calls.log" || true)" -eq 2 ] || {
  echo "boot guard was not replaced and cleared exactly once during successful recovery" >&2
  exit 1
}
[ "$(grep -c '^xray-init restart$' "$TMP/openwrt-calls.log" || true)" -eq "$xray_restarts_before" ] || {
  echo "reconcile started Xray even though the committed direct-only service state was stopped" >&2
  exit 1
}

stale_result=$(adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision")
printf '%s\n' "$stale_result" | grep -F 'stale_timer_ignored=true' >/dev/null
assert_status committed

# Verification failure: rollback restores old config/DNS/Xray and removes only the project-owned absent nft file.
printf 'rollback-config\n' > "$ROUTER_POLICY_CONFIG_PATH"
rm -f "$ACTIVE_NFT"
printf 'rollback-dnsmasq\n' > "$ACTIVE_DNSMASQ"
printf 'rollback-xray\n' > "$ACTIVE_XRAY"
printf '%s\n' \
  'firewall.@defaults[0].flow_offloading=1' \
  'firewall.@defaults[0].flow_offloading_hw=1' > "$TMP/uci-state.env"
printf 'transaction_id=tx_aaaaaaaaaaaaaaaa\nrevision_id=rev_1_aaaaaaaaaaaa\ncandidate_hash=sha256:old\nartifact_manifest_hash=sha256:old\ntransaction_state=committed\n' > "$RUNTIME_DIR/active-transaction.env"

setup_transaction "tx_8899aabbccddeeff" "rev_3_8899aabbccdd" "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677"
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter validate-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter snapshot-current "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter apply-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
rm -f "$STATE_DIR/diagnostics/management.env"
management_unverified=$(adapter verify-management "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision")
printf '%s\n' "$management_unverified" | grep -F 'lan_management_path=false' >/dev/null
printf '%s\n' "$management_unverified" | grep -F 'glinet_uhttpd_path=false' >/dev/null
printf '%s\n' "$management_unverified" | grep -F 'verification_status=UNVERIFIED' >/dev/null
printf 'lan_management_path=true\nglinet_uhttpd_path=true\n' > "$STATE_DIR/diagnostics/management.env"
unverified=$(adapter verify-data-plane "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision")
printf '%s\n' "$unverified" | grep -F 'verification_status=UNVERIFIED' >/dev/null
printf '%s\n' \
  'firewall.@defaults[0].flow_offloading=1' \
  'firewall.@defaults[0].flow_offloading_hw=0' > "$TMP/uci-state.env"
set +e
flow_failure=$(adapter verify-data-plane "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" 2>&1)
flow_failure_rc=$?
set -e
[ "$flow_failure_rc" -eq 5 ] || {
  echo "re-enabled flow offloading did not fail verification: rc=$flow_failure_rc output=$flow_failure" >&2
  exit 1
}
printf '%s\n' "$flow_failure" | grep -F 'verification_status=ERROR' >/dev/null
printf '%s\n' "$flow_failure" | grep -F 'reason=flow_offloading_not_disabled' >/dev/null
adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
assert_status rolled_back
[ "$(cat "$ROUTER_POLICY_CONFIG_PATH")" = "rollback-config" ]
[ ! -e "$ACTIVE_NFT" ] || { echo "absent nft marker did not remove the project file" >&2; exit 1; }
[ "$(cat "$ACTIVE_DNSMASQ")" = "rollback-dnsmasq" ]
[ "$(cat "$ACTIVE_XRAY")" = "rollback-xray" ]
grep -Fx 'revision_id=rev_1_aaaaaaaaaaaa' "$RUNTIME_DIR/active-transaction.env" >/dev/null
grep -Fx 'firewall.@defaults[0].flow_offloading=1' "$TMP/uci-state.env" >/dev/null
grep -Fx 'firewall.@defaults[0].flow_offloading_hw=1' "$TMP/uci-state.env" >/dev/null
reload_count=$(grep -c '^fw4 reload$' "$TMP/openwrt-calls.log")
repeat_result=$(adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision")
printf '%s\n' "$repeat_result" | grep -F 'already_rolled_back=true' >/dev/null
[ "$(grep -c '^fw4 reload$' "$TMP/openwrt-calls.log")" -eq "$reload_count" ] || {
  echo "duplicate rollback reloaded restored state twice" >&2
  exit 1
}

# A pending transaction excludes another prepare; cleanup before apply remains possible with an older active revision.
setup_transaction "tx_1111111111111111" "rev_4_111111111111" "1111111111111111111111111111111111111111111111111111111111111111"
pending_tx="$txid"
pending_revision="$revision"
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$pending_tx" "$pending_revision" >/dev/null
setup_transaction "tx_2222222222222222" "rev_5_222222222222" "2222222222222222222222222222222222222222222222222222222222222222"
set +e
busy_output=$(adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" 2>&1)
busy_rc=$?
set -e
[ "$busy_rc" -eq 75 ] || {
  echo "second prepare was not rejected with EX_TEMPFAIL: rc=$busy_rc output=$busy_output" >&2
  exit 1
}
printf '%s\n' "$busy_output" | grep -F 'another_transaction_is_pending' >/dev/null
adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$pending_tx" "$pending_revision" >/dev/null

# Production helper refuses synthetic diagnostics unless the local test capability is explicit.
setup_transaction "tx_4444444444444444" "rev_6_444444444444" "4444444444444444444444444444444444444444444444444444444444444444"
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
unset ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS
simulation_refused=$(adapter validate-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision")
export ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS=1
printf '%s\n' "$simulation_refused" | grep -F 'verification_status=UNVERIFIED' >/dev/null
printf '%s\n' "$simulation_refused" | grep -F 'reason=simulated_diagnostics_refused' >/dev/null
adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null

# A valid but foreign candidate cannot be paired with the already generated artifacts.
setup_transaction "tx_3333333333333333" "rev_7_333333333333" "3333333333333333333333333333333333333333333333333333333333333333"
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter validate-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter snapshot-current "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
cp "$ROUTER_POLICY_CONFIG_PATH" "$TMP/config-before-foreign-apply"
node -e 'const fs=require("fs"); const path=process.argv[1]; const config=JSON.parse(fs.readFileSync(path, "utf8")); config.policy.max_probe_seconds += 1; fs.writeFileSync(path, JSON.stringify(config, null, 2)+"\n");' "$(to_native_path "$txdir/candidate.json")"
set +e
foreign_output=$(adapter apply-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" 2>&1)
foreign_rc=$?
set -e
[ "$foreign_rc" -ne 0 ] || { echo "foreign candidate was applied with old artifacts" >&2; exit 1; }
printf '%s\n' "$foreign_output" | grep -F 'candidate canonical hash mismatch' >/dev/null
cmp "$TMP/config-before-foreign-apply" "$ROUTER_POLICY_CONFIG_PATH"
adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null

# IP-state rollback ownership: a deployment-ready apply creates kernel policy rules and route-table routes from an empty pre-state; rollback must remove them with no orphans.
rm -f "$MOCK_IP_STATE"
: > "$TMP/openwrt-calls.log"
setup_transaction "tx_5555555555555555" "rev_8_555555555555" "5555555555555555555555555555555555555555555555555555555555555555"
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter validate-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter snapshot-current "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
ip_rules_pre=$("$IP_BIN" -j rule show | tr -d '\n')
ip_routes_pre=$("$IP_BIN" -j route show table 100 | tr -d '\n')
[ "$ip_rules_pre" = "[]" ] || { echo "pre-apply ip rules not empty: $ip_rules_pre" >&2; exit 1; }
[ "$ip_routes_pre" = "[]" ] || { echo "pre-apply ip routes not empty: $ip_routes_pre" >&2; exit 1; }
adapter apply-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
ip_rules_post=$("$IP_BIN" -j rule show | tr -d '\n')
ip_routes_post=$("$IP_BIN" -j route show table 100 | tr -d '\n')
case "$ip_rules_post" in *"10010"*) ;; *) echo "apply did not create project ip rules: $ip_rules_post" >&2; exit 1 ;; esac
case "$ip_routes_post" in *"default"*) ;; *) echo "apply did not create project ip route: $ip_routes_post" >&2; exit 1 ;; esac
adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
ip_rules_after=$("$IP_BIN" -j rule show | tr -d '\n')
ip_routes_after=$("$IP_BIN" -j route show table 100 | tr -d '\n')
[ "$ip_rules_after" = "[]" ] || { echo "rollback left orphan ip rules: $ip_rules_after" >&2; exit 1; }
[ "$ip_routes_after" = "[]" ] || { echo "rollback left orphan ip routes: $ip_routes_after" >&2; exit 1; }
grep -q '^ip .* rule del priority ' "$TMP/openwrt-calls.log" || { echo "rollback did not emit ip rule del" >&2; exit 1; }
grep -q '^ip .* route del ' "$TMP/openwrt-calls.log" || { echo "rollback did not emit ip route del" >&2; exit 1; }

# Managed Zapret lifecycle: validation dry-runs the bound nfqws config, apply starts the queue listener before nft activation, rollback restores stopped/absent state.
rm -f "$ACTIVE_ZAPRET"
"$ZAPRET_INIT" stop >/dev/null 2>&1 || true
: > "$TMP/openwrt-calls.log"
setup_transaction "tx_6666666666666666" "rev_9_666666666666" "6666666666666666666666666666666666666666666666666666666666666666" zapret
adapter prepare "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter validate-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
grep -q '^nfqws @.*nfqws-check.conf$' "$TMP/openwrt-calls.log" || { echo "Zapret candidate was not dry-run validated" >&2; exit 1; }
adapter snapshot-current "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
adapter apply-candidate "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
cmp "$txdir/generated/nfqws.conf" "$ACTIVE_ZAPRET"
grep -Fx 'running' "$TMP/service-state/zapret-init.state" >/dev/null
assert_order '^zapret-init restart$' '^nft -f '
adapter rollback "$ROUTER_POLICY_CONFIG_PATH" "$txid" "$revision" >/dev/null
[ ! -e "$ACTIVE_ZAPRET" ] || { echo "rollback left the managed nfqws config behind" >&2; exit 1; }
grep -Fx 'stopped' "$TMP/service-state/zapret-init.state" >/dev/null

echo "state_transitions_begin"
cat "$TMP/state-transitions.log"
echo "state_transitions_end"
echo "openwrt_adapter_integration_ok=true"
