#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT_ROOT="$ROOT"
TMP="${TMPDIR:-/tmp}/router-policy-prefix-switch-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

SYSTEM_ROOT="$TMP"
PREFIX="$TMP/usr/lib/router-policy"
STATE_DIR="$TMP/etc/router-policy/state"
PREFIX_SWITCH_MARKER="$STATE_DIR/prefix-switch.env"
ROUTER_POLICY_INSTALL_LIB_ONLY=1
export SYSTEM_ROOT PREFIX STATE_DIR PREFIX_SWITCH_MARKER ROUTER_POLICY_INSTALL_LIB_ONLY
# shellcheck source=install.sh
. "$ROOT/install.sh"

# Exercise the real durable-rename helper with a fake sync command. The
# fixture is not a power-loss proof, but it verifies that every prefix rename
# requests a containing-directory flush instead of relying on EXIT traps.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/sync" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "${SYNC_LOG:?}"
SH
chmod +x "$TMP/bin/sync"
SYNC_LOG="$TMP/sync.log"
SYSTEM_ROOT=""
export PATH="$TMP/bin:$PATH" SYNC_LOG SYSTEM_ROOT
mkdir -p "$TMP/rename-source"
printf 'durable\n' > "$TMP/rename-source/value"
durable_rename "$TMP/rename-source" "$TMP/rename-target"
[ -f "$TMP/rename-target/value" ] || { echo "durable rename did not move source" >&2; exit 1; }
grep -F -- "-f $TMP" "$SYNC_LOG" >/dev/null || {
  echo "durable rename did not flush containing directory" >&2
  exit 1
}
SYSTEM_ROOT="$TMP"
export SYSTEM_ROOT

reset_fixture() {
  rm -rf "${TMP:?}/usr" "${TMP:?}/etc"
  mkdir -p "$STATE_DIR" "$(dirname "$PREFIX")"
}

write_marker() {
  phase="$1"
  staged="$PREFIX.install.fixture"
  old="$PREFIX.old.fixture"
  {
    printf 'version=1\n'
    printf 'phase=%s\n' "$phase"
    printf 'prefix=%s\n' "$PREFIX"
    printf 'staged=%s\n' "$staged"
    printf 'old=%s\n' "$old"
  } > "$PREFIX_SWITCH_MARKER"
  chmod 600 "$PREFIX_SWITCH_MARKER"
}

reset_fixture
mkdir -p "$PREFIX/scripts" "$PREFIX.install.fixture/scripts"
printf 'staged\n' > "$PREFIX.install.fixture/scripts/value"
write_marker prepared
recover_prefix_switch
[ -d "$PREFIX" ] && [ ! -e "$PREFIX.install.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture" "$PREFIX.install.fixture/scripts"
printf 'staged\n' > "$PREFIX.install.fixture/scripts/value"
write_marker prepared
recover_prefix_switch
[ "$(cat "$PREFIX/scripts/value")" = staged ] && [ -e "$PREFIX.old.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture" "$PREFIX.install.fixture/scripts"
printf 'staged\n' > "$PREFIX.install.fixture/scripts/value"
write_marker old_moved
recover_prefix_switch
[ "$(cat "$PREFIX/scripts/value")" = staged ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture/scripts"
printf 'old\n' > "$PREFIX.old.fixture/scripts/value"
write_marker old_moved
recover_prefix_switch
[ "$(cat "$PREFIX/scripts/value")" = old ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX/scripts" "$PREFIX.install.fixture/scripts"
printf 'new\n' > "$PREFIX/scripts/value"
printf 'staged\n' > "$PREFIX.install.fixture/scripts/value"
write_marker new_active
recover_prefix_switch
[ "$(cat "$PREFIX/scripts/value")" = new ] && [ ! -e "$PREFIX.install.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX" "$PREFIX.old.fixture" "$PREFIX.install.fixture"
write_marker old_moved
if recover_prefix_switch >/dev/null 2>&1; then
  echo "ambiguous prefix state was accepted" >&2
  exit 1
fi
[ -f "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture" "$PREFIX.install.fixture/scripts"
printf 'staged\n' > "$PREFIX.install.fixture/scripts/value"
write_marker ready_to_activate
recover_prefix_switch
[ "$(cat "$PREFIX/scripts/value")" = staged ] && [ -e "$PREFIX.old.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX/scripts" "$PREFIX.old.fixture"
printf 'new\n' > "$PREFIX/scripts/value"
write_marker ready_to_activate
recover_prefix_switch
[ "$(cat "$PREFIX/scripts/value")" = new ] && [ -e "$PREFIX.old.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

# A stale switch directory is removable only when its top-level shape and
# nested object types match the installer-owned prefix contract.  An unknown
# regular file must fence instead of being deleted by a recursive cleanup.
reset_fixture
mkdir -p "$PREFIX.install.foreign/scripts"
printf 'foreign\n' > "$PREFIX.install.foreign/foreign-runtime"
if remove_owned_prefix_switch_tree "$PREFIX.install.foreign" >/dev/null 2>&1; then
  echo "prefix switch cleanup removed an unowned top-level entry" >&2
  exit 1
fi
[ -f "$PREFIX.install.foreign/foreign-runtime" ]

reset_fixture
mkdir -p "$PREFIX.install.owned/scripts"
printf 'owned\n' > "$PREFIX.install.owned/scripts/value"
remove_owned_prefix_switch_tree "$PREFIX.install.owned"
[ ! -e "$PREFIX.install.owned" ]

# Rollback of the active prefix must use the same bounded ownership proof as
# generation cleanup. An unknown top-level entry is foreign and must survive
# the refusal; the old unconditional rm -rf path would have erased it.
reset_fixture
mkdir -p "$PREFIX/scripts"
printf 'active\n' > "$PREFIX/scripts/value"
printf 'foreign\n' > "$PREFIX/foreign-runtime"
if remove_owned_prefix_switch_tree "$PREFIX" >/dev/null 2>&1; then
  echo "active prefix cleanup removed an unowned top-level entry" >&2
  exit 1
fi
[ -f "$PREFIX/foreign-runtime" ]

# Finalization must use the same ownership proof as crash cleanup. A stale
# old-generation directory with an injected top-level file must fence instead
# of being recursively deleted.
reset_fixture
mkdir -p "$PREFIX.old.fixture/scripts"
printf 'owned\n' > "$PREFIX.old.fixture/scripts/value"
printf 'foreign\n' > "$PREFIX.old.fixture/foreign-runtime"
# finalize_prefix_switch consumes this dynamically-scoped value from the
# sourced installer library; ShellCheck cannot model that cross-file contract.
# shellcheck disable=SC2034
old_prefix="$PREFIX.old.fixture"
if finalize_prefix_switch >/dev/null 2>&1; then
  echo "finalize removed an unowned old-prefix entry" >&2
  exit 1
fi
[ -f "$PREFIX.old.fixture/foreign-runtime" ]

# New install attempts must fence a pre-existing PID-named path instead of
# recursively deleting it before staging a candidate.
grep -F 'untracked prefix switch path already exists' "$PROJECT_ROOT/install.sh" >/dev/null
# OpenWrt ships BusyBox find, which has no GNU `-quit`; installer and
# uninstaller ownership walks must remain target-compatible.
if grep -F -- '-print -quit' "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/uninstall.sh" >/dev/null; then
  echo "installer ownership walk still requires GNU find -quit" >&2
  exit 1
fi

echo "installer_prefix_switch_recovery=true"
echo "installer_prefix_switch_ambiguous_state_blocks=true"
echo "installer_prefix_switch_durable_rename=true"
echo "installer_prefix_switch_cleanup_is_bounded=true"
echo "installer_prefix_rollback_ownership_fence=true"
