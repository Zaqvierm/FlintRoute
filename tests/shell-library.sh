#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-shell-library-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP"

# The legacy shell helper is still shipped for compatibility. Its atomic write
# must never replace the target when writing or applying the requested mode
# fails, and it must not hide chmod errors.
# shellcheck source=../scripts/lib/common.sh
. "$ROOT/scripts/lib/common.sh"

target="$TMP/state.json"
printf 'old\n' > "$target"
chmod 600 "$target"
printf 'new\n' | rp_atomic_write "$target"
[ "$(cat "$target")" = "new" ]
case "$(uname -s 2>/dev/null || true)" in
  Linux*) [ "$(stat -c '%a' "$target")" = "600" ] ;;
  *) echo "mode_check=NOT_RUN_LOCALLY" ;;
esac

chmod() { return 1; }
if printf 'should-not-install\n' | rp_atomic_write "$target"; then
  echo "rp_atomic_write accepted a failed chmod" >&2
  exit 1
fi
[ "$(cat "$target")" = "new" ]
[ ! -e "$target.$$" ]
echo "shell_library_atomic_write=PASS"
