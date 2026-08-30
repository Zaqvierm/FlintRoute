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

# A missing last-good binding is not evidence that the dataplane is empty when
# transaction journals remain. The uninstaller must fence before touching any
# managed path.
MISSING_BINDING_ROOT="$TMP/uninstall-missing-binding"
mkdir -p "$MISSING_BINDING_ROOT/etc/router-policy/state/transactions/rev_1_deadbeef0001/tx_deadbeefdeadbeef"
# The child shell intentionally expands $1; keep the command literal for the
# test fixture rather than interpolating the parent shell's path.
# shellcheck disable=SC2016
missing_binding_output=$(env \
  ROUTER_POLICY_UNINSTALL_LIB_ONLY=1 \
  ROUTER_POLICY_SYSTEM_ROOT="$MISSING_BINDING_ROOT" \
  STATE_DIR="$MISSING_BINDING_ROOT/etc/router-policy/state" \
  ETC_DIR="$MISSING_BINDING_ROOT/etc/router-policy" \
  sh -c 'PROJECT_ROOT="$1"; export PROJECT_ROOT; . "$PROJECT_ROOT/uninstall.sh"; deactivate_committed_dataplane' \
  sh "$PROJECT_ROOT" 2>&1 || true)
printf '%s\n' "$missing_binding_output" | grep -F 'committed transaction binding is missing while transaction journals remain' >/dev/null || {
  echo "uninstaller did not fence missing last-good binding" >&2
  exit 1
}
echo "uninstaller_missing_binding_fenced=true"

# A fixed runtime root is not a blanket ownership grant.  Unknown entries
# must block uninstall before any teardown or recursive deletion can touch
# them.
FOREIGN_RUNTIME_ROOT="$TMP/uninstall-foreign-runtime"
mkdir -p "$FOREIGN_RUNTIME_ROOT/etc/router-policy" "$FOREIGN_RUNTIME_ROOT/tmp/router-policy"
printf 'foreign\n' > "$FOREIGN_RUNTIME_ROOT/tmp/router-policy/foreign.bin"
foreign_runtime_output=$(ROUTER_POLICY_SYSTEM_ROOT="$FOREIGN_RUNTIME_ROOT" \
  BACKUP_DIR="$TMP/foreign-runtime-backup" TAR_BIN="$TMP/fake-tar" \
  sh "$PROJECT_ROOT/uninstall.sh" --uninstall 2>&1 || true)
printf '%s\n' "$foreign_runtime_output" | grep -F 'unowned runtime entry' >/dev/null || {
  echo "uninstaller did not block an unowned runtime entry" >&2
  exit 1
}
[ -f "$FOREIGN_RUNTIME_ROOT/tmp/router-policy/foreign.bin" ]
echo "uninstaller_blocks_unowned_runtime=true"

# Profile teardown is two-phase: a later stop failure must not delete files
# belonging to profiles that were already stopped successfully.
PROFILE_ROOT="$TMP/uninstall-profile-partial"
mkdir -p "$PROFILE_ROOT/etc/router-policy/zapret/profiles" "$PROFILE_ROOT/etc/init.d"
cat > "$PROFILE_ROOT/etc/router-policy/zapret/profiles.manifest" <<EOF
ok|$PROFILE_ROOT/etc/router-policy/zapret/profiles/ok.conf|$PROFILE_ROOT/etc/init.d/router-policy-zapret-ok|200|
bad|$PROFILE_ROOT/etc/router-policy/zapret/profiles/bad.conf|$PROFILE_ROOT/etc/init.d/router-policy-zapret-bad|201|
EOF
printf 'ok\n' > "$PROFILE_ROOT/etc/router-policy/zapret/profiles/ok.conf"
printf 'bad\n' > "$PROFILE_ROOT/etc/router-policy/zapret/profiles/bad.conf"
cat > "$PROFILE_ROOT/etc/init.d/router-policy-zapret-ok" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$PROFILE_ROOT/etc/init.d/router-policy-zapret-bad" <<'SH'
#!/bin/sh
[ "${1:-}" = stop ] && exit 1
exit 0
SH
chmod +x "$PROFILE_ROOT/etc/init.d/router-policy-zapret-ok" "$PROFILE_ROOT/etc/init.d/router-policy-zapret-bad"
# shellcheck disable=SC2016 # command is intentionally evaluated by child shell
profile_partial_output=$(env \
  ROUTER_POLICY_UNINSTALL_LIB_ONLY=1 \
  SYSTEM_ROOT="$PROFILE_ROOT" \
  ETC_DIR="$PROFILE_ROOT/etc/router-policy" \
  INIT_DIR="$PROFILE_ROOT/etc/init.d" \
  ZAPRET_PROFILE_DIR="$PROFILE_ROOT/etc/router-policy/zapret/profiles" \
  ZAPRET_PROFILE_MANIFEST="$PROFILE_ROOT/etc/router-policy/zapret/profiles.manifest" \
  PROFILE_UNINSTALL_SCRIPT="$PROJECT_ROOT/uninstall.sh" \
  sh -c '. "$PROFILE_UNINSTALL_SCRIPT"; remove_owned_profile_resources' 2>&1 || true)
printf '%s\n' "$profile_partial_output" | grep -F 'could not stop router-policy-zapret-bad' >/dev/null || {
  echo "profile teardown failure was not surfaced" >&2
  exit 1
}
[ -f "$PROFILE_ROOT/etc/router-policy/zapret/profiles/ok.conf" ] &&
[ -f "$PROFILE_ROOT/etc/init.d/router-policy-zapret-ok" ] &&
[ -f "$PROFILE_ROOT/etc/router-policy/zapret/profiles.manifest" ]
echo "uninstaller_preserves_profile_manifest_on_partial_stop=true"

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
