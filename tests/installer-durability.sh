#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-installer-durability-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/bin" "$TMP/source" "$TMP/target"

# Exercise the real installer atomic_copy function without touching a host
# system path. The fake tools model a platform where syncing a file works,
# but syncing its parent and the global fallback fail. That failure must be
# returned to the caller; it is not safe to turn it into a warning.
cat > "$TMP/bin/sync" <<'SH'
#!/bin/sh
case "$*" in
  *\.install.*) exit 0 ;;
  *) exit 1 ;;
esac
SH
cat > "$TMP/bin/chown" <<'SH'
#!/bin/sh
exit 0
SH
chmod +x "$TMP/bin/sync" "$TMP/bin/chown"

printf 'source\n' > "$TMP/source/file"
PATH="$TMP/bin:$PATH"
ROUTER_POLICY_INSTALL_LIB_ONLY=1
SYSTEM_ROOT=""
PREFIX="$TMP/prefix"
ETC_DIR="$TMP/etc/router-policy"
STATE_DIR="$TMP/state"
RUNTIME_DIR="$TMP/runtime"
BIN_DIR="$TMP/bin-target"
INIT_DIR="$TMP/init"
RC_DIR="$TMP/rc"
HOTPLUG_IFACE_DIR="$TMP/hotplug/iface"
HOTPLUG_FIREWALL_DIR="$TMP/hotplug/firewall"
DNSMASQ_DIR="$TMP/dnsmasq"
BACKUP_ROOT="$TMP/backups"
BACKUP_DIR="$TMP/backups/current"
SOURCE_BINARY="$TMP/source/file"
SOURCE_HELPER_BINARY="$TMP/source/file"
export ROUTER_POLICY_INSTALL_LIB_ONLY SYSTEM_ROOT PREFIX ETC_DIR STATE_DIR RUNTIME_DIR
export BIN_DIR INIT_DIR RC_DIR HOTPLUG_IFACE_DIR HOTPLUG_FIREWALL_DIR DNSMASQ_DIR
export BACKUP_ROOT BACKUP_DIR SOURCE_BINARY SOURCE_HELPER_BINARY

# shellcheck source=install.sh
. "$ROOT/install.sh"

if atomic_copy "$SOURCE_BINARY" "$TMP/target/file" 600; then
  echo "atomic_copy reported success after an unhandled durability failure" >&2
  exit 1
fi

echo "installer_atomic_copy_sync_failure_is_fatal=true"
