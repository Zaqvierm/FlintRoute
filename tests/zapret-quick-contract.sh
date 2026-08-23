#!/bin/sh
set -eu

case "$(uname -s 2>/dev/null || true)" in
  Linux*) ;;
  *)
    echo "NOT RUN LOCALLY — requires Linux root/process/procfs semantics for Quick runner preflight"
    exit 0
    ;;
esac

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-zapret-quick-contract-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/bin" "$TMP/runtime" "$TMP/catalog"
printf '{}\n' > "$TMP/config.json"

cat > "$TMP/bin/nfqws" <<'SH'
#!/bin/sh
echo 'nfqws version v1.2'
SH
for tool in nft curl setsid su; do
  cp "$TMP/bin/nfqws" "$TMP/bin/$tool"
done
chmod 755 "$TMP/bin"/*

export ROUTER_POLICY_CONFIG="$TMP/config.json"
export NFQWS_BIN="$TMP/bin/nfqws"
export NFT_BIN="$TMP/bin/nft"
export CURL_BIN="$TMP/bin/curl"
export SETSID_BIN="$TMP/bin/setsid"
export SU_BIN="$TMP/bin/su"
export ROUTER_POLICY_RUNTIME_DIR="$TMP/runtime"
export ZAPRET_CATALOG_OUT="$TMP/catalog/catalog.json"
export ZAPRET_CALIBRATION_IPV4=8.8.8.8

# The production queue is a binding, not a value the standalone script may
# invent. Missing/invalid binding must fail before any nft or process action.
if ZAPRET_MANAGED_QUEUE=bad sh "$ROOT/scripts/quick-zapret-check.sh" --apply --mode quick --domain observed.example --bundle-id auto-observed --network-fingerprint "sha256:$(printf '%064d' 0)" > "$TMP/invalid-queue.out" 2> "$TMP/invalid-queue.err"; then
  echo "invalid managed queue unexpectedly passed" >&2
  exit 1
fi
grep -F 'invalid managed production NFQUEUE' "$TMP/invalid-queue.err" >/dev/null
[ -z "$(find "$TMP/runtime" -mindepth 1 -print -quit)" ]

# A pre-resolved target is part of the path proof. Do not accept malformed or
# non-decimal addresses merely because the caller supplied an environment var.
if ZAPRET_MANAGED_QUEUE=200 ZAPRET_CALIBRATION_IPV4=999.1.1.1 sh "$ROOT/scripts/quick-zapret-check.sh" --apply --mode quick --domain observed.example --bundle-id auto-observed --network-fingerprint "sha256:$(printf '%064d' 0)" > "$TMP/invalid-ip.out" 2> "$TMP/invalid-ip.err"; then
  echo "invalid target unexpectedly passed" >&2
  exit 1
fi
grep -F 'invalid pre-resolved IPv4 target' "$TMP/invalid-ip.err" >/dev/null
[ -z "$(find "$TMP/runtime" -mindepth 1 -print -quit)" ]

if grep -F -- '--blockcheck' "$ROOT/scripts/quick-zapret-check.sh"; then
  echo "quick runner contains an upstream blockcheck argument" >&2
  exit 1
fi
grep -F 'profiles="quick-fake quick-fake-ttl3 quick-fake-split quick-managed"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
grep -F "lock_dir=\"\$RUNTIME_DIR/zapret-calibration.lock\"" "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
sh -n "$ROOT/scripts/quick-zapret-check.sh"
echo "quick_runner_contract_preflight=true"
