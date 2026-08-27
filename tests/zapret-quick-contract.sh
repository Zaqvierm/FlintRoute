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
step=setup
trap 'status=$?; if [ "$status" -ne 0 ]; then echo "quick_runner_contract_failed_at=${step:-unknown}" >&2; fi; rm -rf "$TMP"; exit "$status"' EXIT HUP INT TERM
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
step=invalid_queue
if ZAPRET_MANAGED_QUEUE=bad sh "$ROOT/scripts/quick-zapret-check.sh" --apply --mode quick --domain observed.example --bundle-id auto-observed --network-fingerprint "sha256:$(printf '%064d' 0)" > "$TMP/invalid-queue.out" 2> "$TMP/invalid-queue.err"; then
  echo "invalid managed queue unexpectedly passed" >&2
  exit 1
fi
if ! grep -F 'invalid managed production NFQUEUE' "$TMP/invalid-queue.err" >/dev/null; then
  echo "invalid queue diagnostic was not emitted:" >&2
  cat "$TMP/invalid-queue.err" >&2
  exit 1
fi
if [ -n "$(find "$TMP/runtime" -mindepth 1 -print -quit)" ]; then
  echo "invalid queue left runtime resources:" >&2
  find "$TMP/runtime" -mindepth 1 -print >&2
  exit 1
fi

# A pre-resolved target is part of the path proof. Do not accept malformed or
# non-decimal addresses merely because the caller supplied an environment var.
step=invalid_target
if ZAPRET_MANAGED_QUEUE=200 ZAPRET_CALIBRATION_IPV4=999.1.1.1 sh "$ROOT/scripts/quick-zapret-check.sh" --apply --mode quick --domain observed.example --bundle-id auto-observed --network-fingerprint "sha256:$(printf '%064d' 0)" > "$TMP/invalid-ip.out" 2> "$TMP/invalid-ip.err"; then
  echo "invalid target unexpectedly passed" >&2
  exit 1
fi
grep -F 'invalid pre-resolved IPv4 target' "$TMP/invalid-ip.err" >/dev/null
[ -z "$(find "$TMP/runtime" -mindepth 1 -print -quit)" ]

# Embedded OpenWrt commonly has no `su` applet.  The runner must use its
# explicit root-fallback mode (UID 0 remains bound to the owned nft rule) and
# must not fail merely because the optional privilege-drop helper is absent.
if grep -F 'su is unavailable' "$TMP/invalid-ip.err" >/dev/null; then
  echo "missing su was treated as a fatal dependency" >&2
  exit 1
fi

# curl uses the string sentinel `000` when no response was received.  Keep a
# portable shell-level regression for the JSON-number rule: the production
# runner must canonicalise it to `0`, while ordinary HTTP codes stay intact.
step=static_contract
for status in 000 001 200 404; do
  canonical=$(printf '%s' "$status" | sed 's/^0*//')
  [ -n "$canonical" ] || canonical=0
  case "$status:$canonical" in
    000:0|001:1|200:200|404:404) ;;
    *) echo "unexpected HTTP status canonicalisation: $status -> $canonical" >&2; exit 1 ;;
  esac
done
# shellcheck disable=SC2016
grep -F 'http_status=$(printf '\''%s'\'' "$http_status" | sed '\''s/^0*//'\'')' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null

if grep -F -- '--blockcheck' "$ROOT/scripts/quick-zapret-check.sh"; then
  echo "quick runner contains an upstream blockcheck argument" >&2
  exit 1
fi
grep -F 'profiles="general general-alt general-alt2 general-alt4 general-alt6 general-alt10"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
grep -F 'profile_name()' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
# nft diagnostics must not contaminate the machine-readable result stream.
# shellcheck disable=SC2016
grep -F '$NFT_BIN -f "$rules" >&2 || return 1' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
# The catalog must retain the trailing newline hashed in each strategy file.
# shellcheck disable=SC2016
grep -F 'printf "%s", $0; printf "\\n"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
grep -F 'start_parent_watchdog' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
grep -F "lock_dir=\"\$RUNTIME_DIR/zapret-calibration.lock\"" "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
# OpenWrt's BusyBox grep treats a needle beginning with `--` as an option
# unless the option terminator is present.  Keep the regression visible in the
# contract test because this used to surface as a misleading grep usage error.
# The following grep patterns intentionally contain literal shell variables;
# they are contract strings, not commands that this test should expand.
# shellcheck disable=SC2016
grep -F 'grep -Fq -- "$wanted"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
# BusyBox ps has no `-o pgid= -p PID` interface.  Process-group ownership must
# be derived from procfs, otherwise every Quick attempt is an infrastructure
# failure even when nfqws is running.
# shellcheck disable=SC2016
grep -F '"/proc/$pid/stat"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
# shellcheck disable=SC2016
if grep -F 'ps -o pgid= -p "$1"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null; then
  echo "quick runner still depends on unsupported ps pgid formatting" >&2
  exit 1
fi
# The final catalog move must use a destination-side temporary file.  The
# run directory is under /tmp while the production catalog is commonly under
# /etc, so reusing the cleared staging variable would become `cp ... ''`.
# shellcheck disable=SC2016
grep -F 'catalog_tmp="$CATALOG_OUT.tmp.$run_token"' "$ROOT/scripts/quick-zapret-check.sh" >/dev/null
sh -n "$ROOT/scripts/quick-zapret-check.sh"
echo "quick_runner_contract_preflight=true"
