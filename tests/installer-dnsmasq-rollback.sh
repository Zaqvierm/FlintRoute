#!/bin/sh
set -eu

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

mkdir -p "$TMP/managed" "$TMP/state" "$TMP/backups" "$TMP/etc/init.d" "$TMP/bin"
printf 'baseline\n' > "$TMP/managed/observer-marker"
printf 'enabled=1\nrunning=1\n' > "$TMP/dnsmasq.state"

cat > "$TMP/etc/init.d/dnsmasq" <<'SH'
#!/bin/sh
set -eu
state="$DNSMASQ_STATE"
set_state() { sed -i "s/^$1=.*/$1=$2/" "$state"; }
case "${1:-}" in
  enabled) grep -Fx 'enabled=1' "$state" >/dev/null ;;
  running) grep -Fx 'running=1' "$state" >/dev/null ;;
  enable) set_state enabled 1 ;;
  disable) set_state enabled 0 ;;
  start) set_state running 1 ;;
  stop) set_state running 0 ;;
  *) exit 2 ;;
esac
SH
cat > "$TMP/bin/timeout" <<'SH'
#!/bin/sh
shift
exec "$@"
SH
chmod +x "$TMP/etc/init.d/dnsmasq" "$TMP/bin/timeout"

export DNSMASQ_STATE="$TMP/dnsmasq.state"
export PATH="$TMP/bin:$PATH"
export ROUTER_POLICY_INSTALL_LIB_ONLY=1
export ROUTER_POLICY_SYSTEM_ROOT=""
export PREFIX="$TMP/prefix"
export ETC_DIR="$TMP/etc/router-policy"
export STATE_DIR="$TMP/state"
export STATE_DATABASE="$TMP/state/router-policy.bbolt"
export RUNTIME_DIR="$TMP/runtime"
export BIN_DIR="$TMP/bin"
export INIT_DIR="$TMP/etc/init.d"
export RC_DIR="$TMP/etc/rc.d"
export HOTPLUG_IFACE_DIR="$TMP/etc/hotplug.d/iface"
export HOTPLUG_FIREWALL_DIR="$TMP/etc/hotplug.d/firewall"
export DNSMASQ_DIR="$TMP/dnsmasq.d"
export BACKUP_ROOT="$TMP/backups"
export BACKUP_DIR="$TMP/backups/install"
export INSTALL_TARGETS="$TMP/managed"
export ENABLE_SERVICES=dnsmasq
export TIMEOUT_BIN="$TMP/bin/timeout"
export TAR_BIN=tar

# shellcheck disable=SC1091
. "$ROOT/install.sh"

# install.sh intentionally rebuilds its production allowlists at source time;
# replace them with this isolated fixture after loading the library.
INSTALL_TARGETS="$TMP/managed"
# dnsmasq is deliberately not part of the normal enable/disable allowlist;
# snapshot_installation appends its separate runtime record itself.
ENABLE_SERVICES=""
CRITICAL_SYSTEM_DIRS=""
export INSTALL_TARGETS ENABLE_SERVICES CRITICAL_SYSTEM_DIRS

# Keep this fixture focused on service-state restoration, not platform probes.
refresh_install_targets() { :; }
validate_backup_paths() { :; }
validate_critical_system_dirs() { :; }
restore_state_database() { :; }
clear_prefix_switch_marker() { :; }

snapshot_installation
grep -Fx 'dnsmasq|1|1' "$BACKUP_DIR/install-rollback/services.txt" >/dev/null

printf 'candidate\n' > "$TMP/managed/observer-marker"
printf 'enabled=0\nrunning=0\n' > "$TMP/dnsmasq.state"
restore_installation >/dev/null 2>&1

[ "$(cat "$TMP/managed/observer-marker")" = baseline ]
grep -Fx 'enabled=1' "$TMP/dnsmasq.state" >/dev/null
grep -Fx 'running=1' "$TMP/dnsmasq.state" >/dev/null
echo "installer_dnsmasq_runtime_restore_ok=true"
