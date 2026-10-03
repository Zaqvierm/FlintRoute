#!/bin/sh
set -eu
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ]; then
  echo "NOT RUN LOCALLY — requires Linux root/non-root file ownership semantics"
  exit 0
fi
ROOT=$(unset CDPATH; cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/flintroute-state-metadata.XXXXXX)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
chmod 755 "$TMP"
export ROUTER_POLICY_INSTALL_LIB_ONLY=1
export ROUTER_POLICY_SYSTEM_ROOT="$TMP/root"
export BACKUP_ROOT="$TMP/backups"
export BACKUP_DIR="$BACKUP_ROOT/test"
export ROUTER_POLICY_BIN=/bin/true
mkdir -p "$TMP/root/etc/router-policy/state" "$TMP/root/var/run/dnsmasq" \
  "$TMP/root/usr/bin" "$TMP/root/usr/lib" "$TMP/root/etc/init.d" \
  "$TMP/root/etc/hotplug.d"
# shellcheck source=install.sh
. "$ROOT/install.sh"
printf 'database-before\n' > "$STATE_DATABASE"
chown 1:1 "$STATE_DATABASE"
chmod 640 "$STATE_DATABASE"
log="$SYSTEM_ROOT/var/run/dnsmasq/router-policy-observations.log"
printf 'before\n' > "$log"
chown 1:1 "$log"
chmod 640 "$log"
export INSTALL_TARGETS="$log"
snapshot_installation
snapshot_state_database
expected_hash=$(hash_file "$STATE_DATABASE")
printf 'after\n' >> "$log"
chmod 600 "$log"
printf 'database-changed\n' > "$STATE_DATABASE"
chown 0:0 "$STATE_DATABASE"
restore_installation >/dev/null
[ "$(hash_file "$STATE_DATABASE")" = "$expected_hash" ]
[ "$(stat -c '%u:%g:%a' "$STATE_DATABASE")" = 1:1:640 ]
su -s /bin/sh daemon -c "test -r '$STATE_DATABASE' && test -w '$STATE_DATABASE'"
[ "$(cat "$log")" = "$(printf 'before\nafter')" ]
[ "$(stat -c '%u:%g:%a' "$log")" = 1:1:640 ]
if tar -tf "$BACKUP_DIR/install-rollback/files.tar" | grep -F 'router-policy-observations.log' >/dev/null; then
  echo "writer log content was included in rollback archive" >&2
  exit 1
fi
printf 'tampered\n' >> "$BACKUP_DIR/install-rollback/state-database.metadata"
if restore_state_database >/dev/null 2>&1; then
  echo "tampered state access metadata was accepted" >&2
  exit 1
fi
echo "installer_nonroot_state_access_restored=true"
echo "installer_writer_log_not_replayed=true"
echo "installer_state_metadata_tamper_fenced=true"
