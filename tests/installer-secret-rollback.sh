#!/bin/sh
set -eu

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
BACKUP_TMP=$(mktemp -d)
trap 'rm -rf "$TMP" "$BACKUP_TMP"' EXIT HUP INT TERM

# Build the critical directory shape used by the installer safety checks.
mkdir -p "$TMP/etc/init.d" "$TMP/etc/hotplug.d" "$TMP/usr/bin" \
  "$TMP/usr/lib" "$TMP/tmp/dnsmasq.d" "$TMP/etc/router-policy/secrets" \
  "$TMP/backups"
for path in "$TMP" "$TMP/etc" "$TMP/usr" "$TMP/usr/bin" "$TMP/usr/lib" \
  "$TMP/etc/init.d" "$TMP/etc/hotplug.d"; do
  chmod 755 "$path"
done

export ROUTER_POLICY_INSTALL_LIB_ONLY=1
export ROUTER_POLICY_SYSTEM_ROOT="$TMP"
export PREFIX="$TMP/usr/lib/router-policy"
export ETC_DIR="$TMP/etc/router-policy"
export STATE_DIR="$ETC_DIR/state"
export STATE_DATABASE="$STATE_DIR/router-policy.bbolt"
export RUNTIME_DIR="$TMP/tmp/router-policy"
export BIN_DIR="$TMP/usr/bin"
export INIT_DIR="$TMP/etc/init.d"
export RC_DIR="$TMP/etc/rc.d"
export HOTPLUG_IFACE_DIR="$TMP/etc/hotplug.d/iface"
export HOTPLUG_FIREWALL_DIR="$TMP/etc/hotplug.d/firewall"
export DNSMASQ_DIR="$TMP/tmp/dnsmasq.d"
export BACKUP_ROOT="$BACKUP_TMP/backups"
export BACKUP_DIR="$BACKUP_ROOT/install-fixture"

# shellcheck disable=SC1091
. "$ROOT/install.sh"

known="$ETC_DIR/secrets/vpn-subscription-url"
foreign="$ETC_DIR/secrets/foreign-secret"
printf '%s\n' 'old-subscription' > "$known"
printf '%s\n' 'operator-owned' > "$foreign"
chmod 640 "$ETC_DIR/secrets" "$known"
chmod 604 "$foreign"
secret_dir_metadata_before=$(path_metadata "$ETC_DIR/secrets")
known_metadata_before=$(path_metadata "$known")

snapshot_installation
archive="$BACKUP_DIR/install-rollback/files.tar"
manifest="$BACKUP_DIR/install-rollback/manifest.txt"

# The exact managed file is archived; the directory entry and foreign child
# are not recursively copied into the rollback archive.
tar_listing=$(tar -tf "$archive")
printf '%s\n' "$tar_listing" | grep -F 'etc/router-policy/secrets/vpn-subscription-url' >/dev/null
if printf '%s\n' "$tar_listing" | grep -F 'etc/router-policy/secrets/foreign-secret' >/dev/null; then
  echo 'foreign secret leaked into rollback archive' >&2
  exit 1
fi
grep -F "present|$ETC_DIR/secrets|" "$manifest" >/dev/null
grep -F "present|$known|" "$manifest" >/dev/null

# Simulate a failed install changing the owned file and directory metadata.
printf '%s\n' 'candidate-subscription' > "$known"
chmod 700 "$ETC_DIR/secrets"
# An operator changes their unrelated child while the install is in flight.
printf '%s\n' 'operator-updated' > "$foreign"
chmod 600 "$foreign"
foreign_metadata_during=$(path_metadata "$foreign")

restore_installation

[ "$(cat "$known")" = 'old-subscription' ]
[ "$(path_metadata "$ETC_DIR/secrets")" = "$secret_dir_metadata_before" ]
[ "$(path_metadata "$known")" = "$known_metadata_before" ]
[ "$(cat "$foreign")" = 'operator-updated' ]
[ "$(path_metadata "$foreign")" = "$foreign_metadata_during" ]

echo 'installer_secret_rollback_ok=true'
