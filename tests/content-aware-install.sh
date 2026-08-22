#!/bin/sh
set -eu

PROJECT_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-content-install-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/fake-bin" "$TMP/install" "$TMP/adapter"

REAL_MV=$(command -v mv)
MV_LOG="$TMP/mv.log"
export REAL_MV MV_LOG
cat > "$TMP/fake-bin/mv" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$MV_LOG"
[ "${FAIL_MV:-0}" != "1" ] || exit 71
exec "$REAL_MV" "$@"
SH
chmod +x "$TMP/fake-bin/mv"
PATH="$TMP/fake-bin:$PATH"
export PATH

REAL_SYNC=$(command -v sync || true)
if [ -n "$REAL_SYNC" ]; then
  cat > "$TMP/fake-bin/sync" <<'SH'
#!/bin/sh
set -eu
if [ "${FAIL_DIRECTORY_SYNC:-0}" = "1" ] && [ "$#" -gt 0 ] && [ "$1" = "-f" ] && [ -d "${2:-}" ]; then
  exit 73
fi
if [ "${FAIL_DIRECTORY_SYNC:-0}" = "1" ] && [ "$#" -eq 0 ]; then
  exit 74
fi
exec "$REAL_SYNC" "$@"
SH
  chmod +x "$TMP/fake-bin/sync"
  export REAL_SYNC
fi

RUNTIME_DIR="$TMP/install/runtime"
ROUTER_POLICY_INSTALL_LIB_ONLY=1
SYSTEM_ROOT="$TMP/install/system"
export RUNTIME_DIR ROUTER_POLICY_INSTALL_LIB_ONLY SYSTEM_ROOT
# shellcheck source=install.sh
. "$PROJECT_ROOT/install.sh"

source_file="$TMP/install/source"
target_file="$TMP/install/target"
printf 'same\n' > "$source_file"
cp "$source_file" "$target_file"
chmod 600 "$source_file" "$target_file"
before_inode=$(stat -c '%i' "$target_file")
atomic_copy "$source_file" "$target_file" 600
[ "$(stat -c '%i' "$target_file")" = "$before_inode" ]
[ ! -s "$MV_LOG" ]

printf 'changed\n' > "$source_file"
atomic_copy "$source_file" "$target_file" 600
[ "$(cat "$target_file")" = "changed" ]
[ "$(wc -l < "$MV_LOG" | tr -d ' ')" = "1" ]

chmod 644 "$target_file"
if [ "$(stat -c '%a' "$target_file")" = "644" ]; then
  atomic_copy "$source_file" "$target_file" 600
  [ "$(stat -c '%a' "$target_file")" = "600" ]
  [ "$(wc -l < "$MV_LOG" | tr -d ' ')" = "2" ]
fi

ln -s "$source_file" "$TMP/install/symlink-target"
if [ -L "$TMP/install/symlink-target" ]; then
  if atomic_copy "$source_file" "$TMP/install/symlink-target" 600 >/dev/null 2>&1; then
    echo "atomic_copy followed a symlink target" >&2
    exit 1
  fi
fi

printf 'stable\n' > "$target_file"
printf 'replacement\n' > "$source_file"
export FAIL_MV=1
if atomic_copy "$source_file" "$target_file" 600 >/dev/null 2>&1; then
  echo "atomic_copy accepted a failed rename" >&2
  exit 1
fi
unset FAIL_MV
[ "$(cat "$target_file")" = "stable" ]
if find "$TMP/install" -maxdepth 1 -name 'target.install.*' | grep . >/dev/null; then
  echo "atomic_copy left a temporary file after failed rename" >&2
  exit 1
fi

ROUTER_POLICY_ADAPTER_LIB_ONLY=1
RUNTIME_DIR="$TMP/adapter/runtime"
STATE_DIR="$TMP/adapter/state"
export ROUTER_POLICY_ADAPTER_LIB_ONLY RUNTIME_DIR STATE_DIR
set -- noop "$TMP/adapter/config.json" test-run-1
# shellcheck source=openwrt/adapter.sh
. "$PROJECT_ROOT/openwrt/adapter.sh"

adapter_source="$TMP/adapter/source"
adapter_target="$TMP/adapter/target"
printf 'artifact\n' > "$adapter_source"
cp "$adapter_source" "$adapter_target"
chmod 600 "$adapter_source" "$adapter_target"
: > "$MV_LOG"
before_inode=$(stat -c '%i' "$adapter_target")
atomic_install "$adapter_source" "$adapter_target"
[ "$(stat -c '%i' "$adapter_target")" = "$before_inode" ]
[ ! -s "$MV_LOG" ]

printf 'new-artifact\n' > "$adapter_source"
atomic_install "$adapter_source" "$adapter_target"
[ "$(cat "$adapter_target")" = "new-artifact" ]
[ "$(wc -l < "$MV_LOG" | tr -d ' ')" = "1" ]

ln -s "$adapter_source" "$TMP/adapter/symlink-target"
if [ -L "$TMP/adapter/symlink-target" ]; then
  if atomic_install "$adapter_source" "$TMP/adapter/symlink-target" >/dev/null 2>&1; then
    echo "atomic_install followed a symlink target" >&2
    exit 1
  fi
fi

printf 'stable-artifact\n' > "$adapter_target"
printf 'crash-before-rename\n' > "$adapter_source"
export FAIL_MV=1
if atomic_install "$adapter_source" "$adapter_target" >/dev/null 2>&1; then
  echo "atomic_install accepted a failed rename" >&2
  exit 1
fi
unset FAIL_MV
[ "$(cat "$adapter_target")" = "stable-artifact" ]
if find "$TMP/adapter" -maxdepth 1 -name 'target.tmp.*' | grep . >/dev/null; then
  echo "atomic_install left a temporary file after failed rename" >&2
  exit 1
fi

if [ -n "$REAL_SYNC" ]; then
  printf 'fsync-failure-artifact\n' > "$adapter_source"
  export FAIL_DIRECTORY_SYNC=1
  if atomic_install "$adapter_source" "$adapter_target" >/dev/null 2>&1; then
    echo "atomic_install hid a directory fsync failure" >&2
    exit 1
  fi
  unset FAIL_DIRECTORY_SYNC
  grep -q 'fsync_failed' "$RUNTIME_DIR/write-events.log"
fi

echo "content_aware_install_identical_noop=true"
echo "content_aware_install_changed_atomic=true"
echo "content_aware_install_symlink_rejected=true"
echo "content_aware_install_failed_rename_preserves_target=true"
