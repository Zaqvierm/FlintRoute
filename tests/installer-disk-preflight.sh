#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-disk-preflight-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/prefix" "$TMP/backups" "$TMP/etc" "$TMP/scripts" "$TMP/openwrt" "$TMP/bin"
touch "$TMP/source" "$TMP/helper"

cat >"$TMP/bin/df" <<'SH'
#!/bin/sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf '/dev/mock 100000 0 %s 0%% /\n' "$TEST_DF_AVAILABLE"
SH
chmod +x "$TMP/bin/df"
cat >"$TMP/bin/du" <<'SH'
#!/bin/sh
printf '10\t%s\n' "$2"
SH
chmod +x "$TMP/bin/du"

export ROUTER_POLICY_INSTALL_LIB_ONLY=1
export PREFIX="$TMP/prefix"
export BACKUP_ROOT="$TMP/backups"
export ETC_DIR="$TMP/etc"
export SOURCE_BINARY="$TMP/source"
export SOURCE_HELPER_BINARY="$TMP/helper"
export ROOT="$ROOT"
export DF_BIN="$TMP/bin/df"
export DU_BIN="$TMP/bin/du"
# shellcheck source=install.sh
. "$ROOT/install.sh"

TEST_DF_AVAILABLE=70000
export TEST_DF_AVAILABLE
preflight_disk_space >/dev/null

TEST_DF_AVAILABLE=100
export TEST_DF_AVAILABLE
if preflight_disk_space >"$TMP/low.stdout" 2>"$TMP/low.stderr"; then
  echo "disk preflight accepted an undersized filesystem" >&2
  exit 1
fi
grep -F 'insufficient free space' "$TMP/low.stderr" >/dev/null

echo "installer_disk_preflight_bounded=true"
