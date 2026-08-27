#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
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
mkdir -p "$PREFIX" "$PREFIX.install.fixture"
printf 'staged\n' > "$PREFIX.install.fixture/value"
write_marker prepared
recover_prefix_switch
[ -d "$PREFIX" ] && [ ! -e "$PREFIX.install.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture" "$PREFIX.install.fixture"
printf 'staged\n' > "$PREFIX.install.fixture/value"
write_marker prepared
recover_prefix_switch
[ "$(cat "$PREFIX/value")" = staged ] && [ -e "$PREFIX.old.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture" "$PREFIX.install.fixture"
printf 'staged\n' > "$PREFIX.install.fixture/value"
write_marker old_moved
recover_prefix_switch
[ "$(cat "$PREFIX/value")" = staged ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX.old.fixture"
printf 'old\n' > "$PREFIX.old.fixture/value"
write_marker old_moved
recover_prefix_switch
[ "$(cat "$PREFIX/value")" = old ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX" "$PREFIX.install.fixture"
printf 'new\n' > "$PREFIX/value"
printf 'staged\n' > "$PREFIX.install.fixture/value"
write_marker new_active
recover_prefix_switch
[ "$(cat "$PREFIX/value")" = new ] && [ ! -e "$PREFIX.install.fixture" ] && [ ! -e "$PREFIX_SWITCH_MARKER" ]

reset_fixture
mkdir -p "$PREFIX" "$PREFIX.old.fixture"
write_marker old_moved
if recover_prefix_switch >/dev/null 2>&1; then
  echo "ambiguous prefix state was accepted" >&2
  exit 1
fi
[ -f "$PREFIX_SWITCH_MARKER" ]

echo "installer_prefix_switch_recovery=true"
echo "installer_prefix_switch_ambiguous_state_blocks=true"
