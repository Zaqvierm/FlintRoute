#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-installer-test-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/source" "$TMP/state" "$TMP/backup"
echo "fixture" > "$TMP/source/config"

cat > "$TMP/fake-tar" <<'SH'
#!/bin/sh
set -eu
archive=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-cf" ]; then
    archive="$2"
    break
  fi
  shift
done
[ -n "$archive" ] && : > "$archive"
exit 0
SH
chmod +x "$TMP/fake-tar"

BACKUP_DIR="$TMP/backup"
BACKUP_SOURCES="$TMP/source/config"
STATE_DIR="$TMP/state"
TAR_BIN="$TMP/fake-tar"
ROUTER_POLICY_INSTALL_LIB_ONLY=1
export BACKUP_DIR BACKUP_SOURCES STATE_DIR TAR_BIN ROUTER_POLICY_INSTALL_LIB_ONLY
# shellcheck source=install.sh
. "$ROOT/install.sh"

if (backup >/dev/null 2>&1); then
  echo "installer accepted an invalid empty backup" >&2
  exit 1
fi
if [ -f "$STATE_DIR/last-backup-path" ]; then
  echo "installer continued after invalid backup" >&2
  exit 1
fi
echo "installer_invalid_backup_blocked=true"
