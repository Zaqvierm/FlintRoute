#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT_ROOT="$ROOT"
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

# Export backups must not carry modes for synthetic staging parents.  Archive
# a nested source with the installer's 077 umask and assert that only the
# allowlisted file is present, never `source/` or other directory members.
mkdir -p "$TMP/source/nested"
printf 'nested-fixture\n' > "$TMP/source/nested/file"
BACKUP_DIR="$TMP/valid-backup"
BACKUP_ROOT="$TMP"
BACKUP_SOURCES="$TMP/source"
STATE_DIR="$TMP/state-valid"
TAR_BIN=tar
mkdir -p "$STATE_DIR"
export BACKUP_ROOT BACKUP_DIR BACKUP_SOURCES STATE_DIR TAR_BIN
backup >/dev/null
archive_members=$(tar -tf "$BACKUP_DIR/config.tar")
expected_member="${TMP#/}/source/nested/file"
printf '%s\n' "$archive_members" | grep -Fx "$expected_member" >/dev/null || {
  echo "valid backup omitted allowlisted file" >&2
  exit 1
}
if printf '%s\n' "$archive_members" | grep -Eq '/$|^(source|source/nested)/$'; then
  echo "valid backup carried synthetic directory metadata" >&2
  exit 1
fi
echo "installer_backup_excludes_synthetic_directories=true"

SYSTEM_ROOT="$TMP/uninstall-root"
mkdir -p "$SYSTEM_ROOT/etc/router-policy" "$SYSTEM_ROOT/usr/bin"
printf 'config\n' > "$SYSTEM_ROOT/etc/router-policy/default.json"
printf 'binary\n' > "$SYSTEM_ROOT/usr/bin/router-policy"
if BACKUP_DIR="$TMP/uninstall-backup" ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT" TAR_BIN="$TMP/fake-tar" sh "$PROJECT_ROOT/uninstall.sh" --uninstall >/dev/null 2>&1; then
  echo "uninstaller accepted an invalid empty backup" >&2
  exit 1
fi
if [ ! -f "$SYSTEM_ROOT/usr/bin/router-policy" ]; then
  echo "uninstaller deleted files after backup failure" >&2
  exit 1
fi
echo "uninstaller_invalid_backup_blocked=true"

# The uninstaller must reject environment-derived paths that resolve through
# a parent or use ambiguous separator spelling before it reaches tar/rm.
unsafe_root="$TMP/uninstall-root/.."
unsafe_output=$(ROUTER_POLICY_SYSTEM_ROOT="$unsafe_root" \
  BACKUP_DIR="$TMP/unsafe-uninstall-backup" \
  TAR_BIN="$TMP/fake-tar" \
  sh "$PROJECT_ROOT/uninstall.sh" --uninstall 2>&1 || true)
printf '%s\n' "$unsafe_output" | grep -Eq 'non-standard project prefix|symlink in owned path|backup directory is outside|invalid' || {
  echo "uninstaller did not reject lexical traversal root" >&2
  exit 1
}
echo "uninstaller_rejects_lexical_path_traversal=true"
