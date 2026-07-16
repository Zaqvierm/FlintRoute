#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
TMP="${TMPDIR:-/tmp}/router-policy-installer-lifecycle-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

SYSTEM_ROOT="$TMP/root"
BACKUP_BASE="$TMP/backups"
SOURCE_BINARY="$TMP/router-policy-source"
FAKE_CALL_LOG="$TMP/router-policy-calls.log"
BACKUP_SOURCES="$SYSTEM_ROOT/etc/config/network $SYSTEM_ROOT/etc/router-policy"
mkdir -p "$SYSTEM_ROOT/etc/config" "$BACKUP_BASE"
printf 'network-fixture\n' > "$SYSTEM_ROOT/etc/config/network"

write_fake_binary() {
  version="$1"
  validate_status="$2"
  cat > "$SOURCE_BINARY" <<SH
#!/bin/sh
printf '%s\n' "$version:\$*" >> "\$FAKE_CALL_LOG"
case "\${1:-}" in
  validate-config) exit $validate_status ;;
  auth)
    [ "\${2:-}" = "setup-token" ] && [ "\${3:-}" = "--if-needed" ] || exit 2
    printf '{"setup_required":false}\n'
    ;;
  *) exit 2 ;;
esac
SH
  chmod +x "$SOURCE_BINARY"
}

run_install() {
  BACKUP_DIR="$1" \
  ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT" \
  SOURCE_BINARY="$SOURCE_BINARY" \
  BACKUP_SOURCES="$BACKUP_SOURCES" \
  FAKE_CALL_LOG="$FAKE_CALL_LOG" \
  sh "$ROOT/install.sh" --install
}

write_fake_binary v1 0
run_install "$BACKUP_BASE/first" >/dev/null
[ -x "$SYSTEM_ROOT/usr/bin/router-policy" ]
[ -f "$SYSTEM_ROOT/usr/lib/router-policy/openwrt/adapter.sh" ]
[ -f "$SYSTEM_ROOT/etc/init.d/router-policy" ]
grep -F 'v1:auth setup-token --if-needed' "$FAKE_CALL_LOG" >/dev/null

printf '{"local":"preserved"}\n' > "$SYSTEM_ROOT/etc/router-policy/config/default.json"
write_fake_binary v2 0
run_install "$BACKUP_BASE/upgrade" >/dev/null
grep -F '"local":"preserved"' "$SYSTEM_ROOT/etc/router-policy/config/default.json" >/dev/null
grep -F 'v2:validate-config' "$FAKE_CALL_LOG" >/dev/null
grep -F 'v2:auth setup-token --if-needed' "$FAKE_CALL_LOG" >/dev/null
[ -f "$SYSTEM_ROOT/etc/router-policy/config/factory-default.json" ]

cp "$SYSTEM_ROOT/usr/bin/router-policy" "$TMP/expected-v2"
printf 'stable-prefix\n' > "$SYSTEM_ROOT/usr/lib/router-policy/local-marker"
write_fake_binary broken 1
if run_install "$BACKUP_BASE/broken" >/dev/null 2>&1; then
  echo "installer accepted an invalid upgrade" >&2
  exit 1
fi
cmp "$TMP/expected-v2" "$SYSTEM_ROOT/usr/bin/router-policy"
[ "$(cat "$SYSTEM_ROOT/usr/lib/router-policy/local-marker")" = "stable-prefix" ]
grep -F '"local":"preserved"' "$SYSTEM_ROOT/etc/router-policy/config/default.json" >/dev/null

BACKUP_DIR="$BACKUP_BASE/uninstall" \
ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT" \
sh "$ROOT/uninstall.sh" --uninstall >/dev/null
[ ! -e "$SYSTEM_ROOT/usr/bin/router-policy" ]
[ ! -e "$SYSTEM_ROOT/usr/lib/router-policy" ]
[ ! -e "$SYSTEM_ROOT/etc/init.d/router-policy" ]
[ -f "$SYSTEM_ROOT/etc/router-policy/config/default.json" ]
[ -s "$BACKUP_BASE/uninstall/router-policy-etc.tar" ]
grep -E '^sha256=[0-9a-f]{64}$' "$BACKUP_BASE/uninstall/manifest.txt" >/dev/null

RUNTIME_DIR="$SYSTEM_ROOT/tmp/router-policy"
mkdir -p "$TMP/fake-bin" "$RUNTIME_DIR"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
[ "$count" -ge 3 ] || exit 1
printf '{"status":"ok"}\n' > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
HEALTH_COUNTER="$TMP/health-attempts"
PATH="$TMP/fake-bin:$PATH"
ROUTER_POLICY_INSTALL_LIB_ONLY=1
export HEALTH_COUNTER PATH ROUTER_POLICY_INSTALL_LIB_ONLY RUNTIME_DIR
# shellcheck source=install.sh
. "$ROOT/install.sh"
wait_control_health >/dev/null
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

echo "installer_clean_install=true"
echo "installer_idempotent_upgrade=true"
echo "installer_failed_upgrade_rollback=true"
echo "installer_verified_uninstall=true"
echo "installer_waits_for_control_health=true"
