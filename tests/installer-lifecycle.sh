#!/bin/sh
# These globals are intentionally assigned for functions loaded from
# install.sh; static analysis cannot see their cross-file consumers.
# shellcheck disable=SC2034
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT_ROOT="$ROOT"
TMP="${TMPDIR:-/tmp}/router-policy-installer-lifecycle-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

SYSTEM_ROOT="$TMP/root"
BACKUP_BASE="$TMP/backups"
SOURCE_BINARY="$TMP/router-policy-source"
SOURCE_HELPER_BINARY="$TMP/router-policy-helper-source"
FAKE_CALL_LOG="$TMP/router-policy-calls.log"
SERVICE_CONTROL_LOG="$TMP/service-control.log"
BACKUP_SOURCES="$SYSTEM_ROOT/etc/config/network $SYSTEM_ROOT/etc/router-policy"
mkdir -p "$SYSTEM_ROOT/etc/config" "$SYSTEM_ROOT/usr/bin" "$SYSTEM_ROOT/usr/lib" \
  "$SYSTEM_ROOT/etc/init.d" "$SYSTEM_ROOT/etc/hotplug.d" "$BACKUP_BASE"
chmod 755 "$SYSTEM_ROOT" "$SYSTEM_ROOT/etc" "$SYSTEM_ROOT/etc/config" \
  "$SYSTEM_ROOT/usr" "$SYSTEM_ROOT/usr/bin" "$SYSTEM_ROOT/usr/lib" \
  "$SYSTEM_ROOT/etc/init.d" "$SYSTEM_ROOT/etc/hotplug.d"
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
  backup) exit 0 ;;
  internal-verify-state-backup) exit 0 ;;
  internal-health-field)
    shift
    field=""
    file=""
    while [ "\$#" -gt 0 ]; do
      case "\$1" in
        --field) field="\$2"; shift 2 ;;
        --path) file="\$2"; shift 2 ;;
        *) exit 2 ;;
      esac
    done
    [ -n "\$field" ] && [ -f "\$file" ] || exit 2
    tr '{},' '\n' < "\$file" | sed -n "s/^[[:space:]]*\"\$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*$/\1/p" | head -n 1
    ;;
  *) exit 2 ;;
esac
SH
  chmod +x "$SOURCE_BINARY"
}

run_install() {
  BACKUP_DIR="$1"
  BACKUP_ROOT="$BACKUP_BASE"
  ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT"
  export BACKUP_DIR BACKUP_ROOT ROUTER_POLICY_SYSTEM_ROOT SOURCE_BINARY SOURCE_HELPER_BINARY BACKUP_SOURCES FAKE_CALL_LOG
  sh "$ROOT/install.sh" --install
}

install_service_sentinels() {
  for service in router-policy-dns-observer router-policy-boot-guard router-policy-helper router-policy router-policy-watchdog router-policy-xray router-policy-zapret; do
    cat > "$SYSTEM_ROOT/etc/init.d/$service" <<'SH'
#!/bin/sh
printf '%s\n' "$0:$*" >> "$SERVICE_CONTROL_LOG"
exit 1
SH
    chmod +x "$SYSTEM_ROOT/etc/init.d/$service"
  done
}

export SERVICE_CONTROL_LOG

write_fake_binary v1 0
cp "$SOURCE_BINARY" "$SOURCE_HELPER_BINARY"
run_install "$BACKUP_BASE/first" >/dev/null
[ -x "$SYSTEM_ROOT/usr/bin/router-policy" ]
[ -f "$SYSTEM_ROOT/usr/lib/router-policy/openwrt/adapter.sh" ]
[ -f "$SYSTEM_ROOT/etc/init.d/router-policy" ]
[ -f "$SYSTEM_ROOT/etc/router-policy/helper.env" ]
grep -Fx 'peer_uid=1' "$SYSTEM_ROOT/etc/router-policy/helper.env" >/dev/null
grep -Fx 'socket=/var/run/router-policy/helper.sock' "$SYSTEM_ROOT/etc/router-policy/helper.env" >/dev/null
[ "$(cat "$SYSTEM_ROOT/etc/router-policy/config/listener.conf")" = "$(cat "$ROOT/config/listener.conf")" ]
grep -F 'v1:auth setup-token --if-needed' "$FAKE_CALL_LOG" >/dev/null
auth_line=$(grep -n 'v1:auth setup-token --if-needed' "$FAKE_CALL_LOG" | head -n 1 | cut -d: -f1)
prune_line=$(grep -n 'v1:backup prune' "$FAKE_CALL_LOG" | head -n 1 | cut -d: -f1)
[ -n "$auth_line" ] && [ -n "$prune_line" ] && [ "$prune_line" -gt "$auth_line" ] || {
  echo "installer pruned backups before post-install success" >&2
  exit 1
}
snapshot_archive="$BACKUP_BASE/first/install-rollback/files.tar"
if tar -tf "$snapshot_archive" | grep -Eq '^(usr|usr/lib|etc|etc/init\.d|etc/hotplug\.d)/?$'; then
  echo "installer archived synthetic system parent metadata" >&2
  exit 1
fi
install_service_sentinels

mkdir -p "$SYSTEM_ROOT/usr/lib/router-policy/components/zapret/v72.13"
printf 'managed-runtime\n' > "$SYSTEM_ROOT/usr/lib/router-policy/components/zapret/v72.13/blockcheck.sh"

printf '{"local":"preserved"}\n' > "$SYSTEM_ROOT/etc/router-policy/config/default.json"
printf 'listen_address=192.0.2.1:8787\nallow_firewalled_bind=1\n' > "$SYSTEM_ROOT/etc/router-policy/config/listener.conf"
write_fake_binary v2 0
run_install "$BACKUP_BASE/upgrade" >/dev/null
grep -F '"local":"preserved"' "$SYSTEM_ROOT/etc/router-policy/config/default.json" >/dev/null
grep -F 'listen_address=192.0.2.1:8787' "$SYSTEM_ROOT/etc/router-policy/config/listener.conf" >/dev/null
grep -F 'v2:validate-config' "$FAKE_CALL_LOG" >/dev/null
grep -F 'v2:auth setup-token --if-needed' "$FAKE_CALL_LOG" >/dev/null
[ -f "$SYSTEM_ROOT/etc/router-policy/config/factory-default.json" ]
[ "$(cat "$SYSTEM_ROOT/usr/lib/router-policy/components/zapret/v72.13/blockcheck.sh")" = "managed-runtime" ]
install_service_sentinels

write_fake_binary v1-downgrade 0
run_install "$BACKUP_BASE/downgrade" >/dev/null
grep -F '"local":"preserved"' "$SYSTEM_ROOT/etc/router-policy/config/default.json" >/dev/null
grep -F 'v1-downgrade:validate-config' "$FAKE_CALL_LOG" >/dev/null
grep -F 'v1-downgrade:auth setup-token --if-needed' "$FAKE_CALL_LOG" >/dev/null
install_service_sentinels

write_fake_binary v2 0
run_install "$BACKUP_BASE/restore-current" >/dev/null
grep -F '"local":"preserved"' "$SYSTEM_ROOT/etc/router-policy/config/default.json" >/dev/null
install_service_sentinels

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
for critical_dir in "$SYSTEM_ROOT" "$SYSTEM_ROOT/etc" "$SYSTEM_ROOT/usr" "$SYSTEM_ROOT/usr/bin" "$SYSTEM_ROOT/usr/lib" "$SYSTEM_ROOT/etc/init.d" "$SYSTEM_ROOT/etc/hotplug.d"; do
  [ "$(stat -c '%a' "$critical_dir")" = "755" ] || {
    echo "installer rollback changed critical parent mode: $critical_dir" >&2
    exit 1
  }
done
install_service_sentinels

# Device-scoped Zapret artifacts are removed only from the manifest-bound
# config/init paths. A foreign file in the same directory must survive.
mkdir -p "$SYSTEM_ROOT/etc/router-policy/zapret/profiles"
printf 'tv-q208|%s|%s|208\n' \
  "$SYSTEM_ROOT/etc/router-policy/zapret/profiles/tv-q208.conf" \
  "$SYSTEM_ROOT/etc/init.d/router-policy-zapret-tv-q208" \
  > "$SYSTEM_ROOT/etc/router-policy/zapret/profiles.manifest"
printf 'managed-profile\n' > "$SYSTEM_ROOT/etc/router-policy/zapret/profiles/tv-q208.conf"
printf '#!/bin/sh\nexit 0\n' > "$SYSTEM_ROOT/etc/init.d/router-policy-zapret-tv-q208"
chmod 600 "$SYSTEM_ROOT/etc/router-policy/zapret/profiles.manifest" \
  "$SYSTEM_ROOT/etc/router-policy/zapret/profiles/tv-q208.conf"
chmod 755 "$SYSTEM_ROOT/etc/init.d/router-policy-zapret-tv-q208"
printf 'foreign-profile-file\n' > "$SYSTEM_ROOT/etc/router-policy/zapret/profiles/foreign.conf"

BACKUP_DIR="$BACKUP_BASE/uninstall" \
ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT" \
FAKE_CALL_LOG="$FAKE_CALL_LOG" \
sh "$ROOT/uninstall.sh" --uninstall >/dev/null
[ ! -e "$SYSTEM_ROOT/usr/bin/router-policy" ]
[ ! -e "$SYSTEM_ROOT/usr/lib/router-policy" ]
[ ! -e "$SYSTEM_ROOT/etc/init.d/router-policy" ]
[ ! -e "$SYSTEM_ROOT/etc/router-policy/zapret/profiles.manifest" ]
[ ! -e "$SYSTEM_ROOT/etc/router-policy/zapret/profiles/tv-q208.conf" ]
[ ! -e "$SYSTEM_ROOT/etc/init.d/router-policy-zapret-tv-q208" ]
[ -f "$SYSTEM_ROOT/etc/router-policy/zapret/profiles/foreign.conf" ]
[ -f "$SYSTEM_ROOT/etc/router-policy/config/default.json" ]
[ -s "$BACKUP_BASE/uninstall/router-policy-etc.tar" ]
grep -E '^sha256=[0-9a-f]{64}$' "$BACKUP_BASE/uninstall/manifest.txt" >/dev/null
[ ! -e "$SERVICE_CONTROL_LOG" ]
if grep -Eq '(^|[[:space:]])fw4[[:space:]]+reload' "$ROOT/uninstall.sh"; then
  echo "uninstaller performs an unscoped global firewall reload" >&2
  exit 1
fi
if ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT" PREFIX="$SYSTEM_ROOT/usr/lib/not-router-policy" \
  sh "$ROOT/uninstall.sh" --uninstall >/dev/null 2>&1; then
  echo "uninstaller accepted a non-standard recursive project prefix" >&2
  exit 1
fi
if ROUTER_POLICY_SYSTEM_ROOT="$SYSTEM_ROOT" RUNTIME_DIR="$SYSTEM_ROOT/tmp/not-router-policy" \
  sh "$ROOT/uninstall.sh" --uninstall >/dev/null 2>&1; then
  echo "uninstaller accepted a non-standard recursive runtime root" >&2
  exit 1
fi

RUNTIME_DIR="$SYSTEM_ROOT/tmp/router-policy"
mkdir -p "$TMP/fake-bin" "$RUNTIME_DIR"
HEALTH_CANDIDATE_HASH='sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
HEALTH_ARTIFACT_HASH='sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
export HEALTH_CANDIDATE_HASH HEALTH_ARTIFACT_HASH
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
[ "$count" -ge 3 ] || exit 1
printf '{"data":{"active_revision":"rev_1_test","active_candidate_hash":"%s","active_artifact_manifest_hash":"%s","recovery_status":"ok","status":"ok"}}\n' "$HEALTH_CANDIDATE_HASH" "$HEALTH_ARTIFACT_HASH" > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
cat > "$TMP/fake-bin/sleep" <<'SH'
#!/bin/sh
:
SH
chmod +x "$TMP/fake-bin/sleep"
HEALTH_COUNTER="$TMP/health-attempts"
PATH="$TMP/fake-bin:$PATH"
ROUTER_POLICY_INSTALL_LIB_ONLY=1
ROUTER_POLICY_HEALTH_ATTEMPTS=3
export HEALTH_COUNTER PATH ROUTER_POLICY_INSTALL_LIB_ONLY RUNTIME_DIR ROUTER_POLICY_HEALTH_ATTEMPTS
# shellcheck source=install.sh
. "$ROOT/install.sh"

# Installer health must follow the explicitly configured local management
# listener instead of assuming loopback.  A synthetic SYSTEM_ROOT has no real
# network namespace, so the resolver accepts its fixture address; production
# OpenWrt additionally proves the address is assigned by `ip -4 addr`.
printf 'listen_address=192.0.2.1:8787\nallow_firewalled_bind=1\n' > "$SYSTEM_ROOT/etc/router-policy/config/listener.conf"
[ "$(resolve_control_health_url)" = "http://192.0.2.1:8787/api/v1/health" ]
printf 'listen_address=127.0.0.1:8787\nallow_firewalled_bind=0\n' > "$SYSTEM_ROOT/etc/router-policy/config/listener.conf"
wait_control_health >/dev/null
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

HEALTH_COUNTER="$TMP/recovery-required-health-attempts"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
printf '{"data":{"active_revision":"rev_1_test","active_candidate_hash":"%s","active_artifact_manifest_hash":"%s","recovery_status":"recovery_required","recovery_commit_phase":"control_plane_committed","status":"ok"}}\n' "$HEALTH_CANDIDATE_HASH" "$HEALTH_ARTIFACT_HASH" > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
if wait_control_health >/dev/null 2>&1; then
  echo "installer accepted fenced recovery_required health" >&2
  exit 1
fi
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

HEALTH_COUNTER="$TMP/hash-health-attempts"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
printf '{"data":{"active_revision":"rev_1_test","active_candidate_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","active_artifact_manifest_hash":"%s","recovery_status":"ok","status":"ok"}}\n' "$HEALTH_ARTIFACT_HASH" > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
if wait_control_health rev_1_test "$HEALTH_CANDIDATE_HASH" >/dev/null 2>&1; then
  echo "installer accepted a mismatched active candidate hash" >&2
  exit 1
fi
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

HEALTH_COUNTER="$TMP/missing-hash-health-attempts"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
printf '{"data":{"active_revision":"rev_1_test","recovery_status":"ok","status":"ok"}}\n' > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
if wait_control_health rev_1_test >/dev/null 2>&1; then
  echo "installer accepted health without generation hashes" >&2
  exit 1
fi
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

HEALTH_COUNTER="$TMP/unproven-not-required-attempts"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
printf '{"data":{"active_revision":"rev_1_test","active_candidate_hash":"%s","active_artifact_manifest_hash":"","recovery_status":"not_required","recovery_commit_phase":"","status":"ok"}}\n' "$HEALTH_CANDIDATE_HASH" > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
if wait_control_health >/dev/null 2>&1; then
  echo "installer accepted unproven not_required health" >&2
  exit 1
fi
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

HEALTH_COUNTER="$TMP/degraded-health-attempts"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
printf '{"data":{"active_revision":"rev_1_test","active_candidate_hash":"%s","active_artifact_manifest_hash":"%s","recovery_status":"error","status":"degraded"}}\n' "$HEALTH_CANDIDATE_HASH" "$HEALTH_ARTIFACT_HASH" > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
if wait_control_health >/dev/null 2>&1; then
  echo "installer accepted degraded control-plane health" >&2
  exit 1
fi
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

HEALTH_COUNTER="$TMP/revision-health-attempts"
cat > "$TMP/fake-bin/wget" <<'SH'
#!/bin/sh
set -eu
count=0
[ ! -f "$HEALTH_COUNTER" ] || count=$(cat "$HEALTH_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$HEALTH_COUNTER"
printf '{"data":{"active_revision":"rev_2_changed","active_candidate_hash":"%s","active_artifact_manifest_hash":"%s","recovery_status":"ok","status":"ok"}}\n' "$HEALTH_CANDIDATE_HASH" "$HEALTH_ARTIFACT_HASH" > "$3"
SH
chmod +x "$TMP/fake-bin/wget"
if wait_control_health rev_1_expected >/dev/null 2>&1; then
  echo "installer accepted a changed active revision during upgrade" >&2
  exit 1
fi
[ "$(cat "$HEALTH_COUNTER")" = "3" ]

MODE_TARGET="$TMP/mode-target"
printf 'mode-check\n' > "$MODE_TARGET"
chmod 600 "$MODE_TARGET"
# shellcheck disable=SC2329 # this shadows stat to prove the mode check is portable.
stat() {
  echo "external stat must not be called" >&2
  return 99
}
regular_file_mode_matches "$MODE_TARGET" 600
if regular_file_mode_matches "$MODE_TARGET" 755; then
  echo "portable mode check accepted the wrong mode" >&2
  exit 1
fi
unset -f stat

# Supported OpenWrt images may not ship the stat applet.  Force the
# installer down its ls -ln fallback and verify it still captures the mode
# needed by the critical-directory and rollback invariants.
NO_STAT_BIN="$TMP/no-stat-bin"
mkdir -p "$NO_STAT_BIN"
cat > "$NO_STAT_BIN/stat" <<'SH'
#!/bin/sh
exit 127
SH
chmod +x "$NO_STAT_BIN/stat"
ORIGINAL_PATH="$PATH"
PATH="$NO_STAT_BIN:$PATH"
fallback_metadata=$(path_metadata "$MODE_TARGET")
fallback_mode=${fallback_metadata%%|*}
[ "$fallback_mode" = "600" ] || {
  echo "installer stat fallback reported wrong mode: $fallback_metadata" >&2
  exit 1
}
PATH="$ORIGINAL_PATH"

LEGACY_ROOT="$TMP/legacy-maintenance"
mkdir -p "$LEGACY_ROOT/etc/router-policy/config" "$LEGACY_ROOT/etc/init.d"
cat > "$LEGACY_ROOT/router-policy" <<'SH'
#!/bin/sh
exit 2
SH
cat > "$LEGACY_ROOT/etc/init.d/router-policy-watchdog" <<'SH'
#!/bin/sh
printf '%s\n' "$1" >> "$LEGACY_WATCHDOG_LOG"
[ "$1" = "running" ] || [ "$1" = "stop" ]
SH
cat > "$LEGACY_ROOT/etc/init.d/router-policy" <<'SH'
#!/bin/sh
[ "$1" = "running" ]
SH
chmod +x "$LEGACY_ROOT/router-policy" "$LEGACY_ROOT/etc/init.d/router-policy" "$LEGACY_ROOT/etc/init.d/router-policy-watchdog"
SYSTEM_ROOT=""
ROUTER_POLICY_BIN="$LEGACY_ROOT/router-policy"
ETC_DIR="$LEGACY_ROOT/etc/router-policy"
INIT_DIR="$LEGACY_ROOT/etc/init.d"
LEGACY_WATCHDOG_LOG="$LEGACY_ROOT/watchdog.log"
export LEGACY_WATCHDOG_LOG
if begin_maintenance >"$LEGACY_ROOT/maintenance.out" 2>&1; then
  echo "installer accepted a running controller without maintenance support" >&2
  exit 1
fi
grep -F 'running controller cannot enter maintenance' "$LEGACY_ROOT/maintenance.out" >/dev/null
if [ -e "$LEGACY_WATCHDOG_LOG" ]; then
  echo "installer touched the watchdog after refusing incompatible controller" >&2
  exit 1
fi

RUNTIME_PREFLIGHT_BIN="$TMP/runtime-preflight-bin"
mkdir -p "$RUNTIME_PREFLIGHT_BIN" "$TMP/no-installed-services"
cat > "$RUNTIME_PREFLIGHT_BIN/timeout" <<'SH'
#!/bin/sh
shift
exec "$@"
SH
cat > "$RUNTIME_PREFLIGHT_BIN/ubus" <<'SH'
#!/bin/sh
exit "${FAKE_UBUS_STATUS:-0}"
SH
chmod +x "$RUNTIME_PREFLIGHT_BIN/timeout" "$RUNTIME_PREFLIGHT_BIN/ubus"
TIMEOUT_BIN="$RUNTIME_PREFLIGHT_BIN/timeout"
UBUS_BIN="$RUNTIME_PREFLIGHT_BIN/ubus"
INIT_DIR="$TMP/no-installed-services"
FAKE_UBUS_STATUS=1
export FAKE_UBUS_STATUS
if preflight_runtime >"$TMP/ubus-failure.out" 2>&1; then
  echo "installer accepted an unavailable ubus" >&2
  exit 1
fi
grep -F 'install blocked: ubus system state is unavailable' "$TMP/ubus-failure.out" >/dev/null
FAKE_UBUS_STATUS=0
export FAKE_UBUS_STATUS
preflight_runtime
INIT_DIR="$LEGACY_ROOT/etc/init.d"
if preflight_runtime >"$TMP/legacy-controller-preflight.out" 2>&1; then
  echo "runtime preflight accepted a running legacy controller" >&2
  exit 1
fi
grep -F 'running controller does not support safe maintenance' "$TMP/legacy-controller-preflight.out" >/dev/null
INIT_DIR="$TMP/no-installed-services"

DELAYED_STOP_INIT="$TMP/delayed-stop-init"
DELAYED_STOP_STATE="$TMP/delayed-stop-state"
cat > "$DELAYED_STOP_INIT" <<'SH'
#!/bin/sh
case "$1" in
  stop)
    printf '2\n' > "$DELAYED_STOP_STATE"
    ;;
  running)
    remaining=$(cat "$DELAYED_STOP_STATE" 2>/dev/null || printf '0')
    if [ "$remaining" -gt 0 ]; then
      printf '%s\n' "$((remaining - 1))" > "$DELAYED_STOP_STATE"
      exit 0
    fi
    exit 1
    ;;
esac
SH
chmod +x "$DELAYED_STOP_INIT"
export DELAYED_STOP_STATE
printf '2\n' > "$DELAYED_STOP_STATE"
wait_service_stopped "$DELAYED_STOP_INIT"

SERVICE_STATE_FIXTURE="$TMP/service-state-fixture"
mkdir -p "$SERVICE_STATE_FIXTURE/install-rollback"
cat > "$SERVICE_STATE_FIXTURE/install-rollback/services.txt" <<'EOF'
router-policy|1|1
router-policy-watchdog|1|1
router-policy-xray|1|0
router-policy-zapret|0|0
EOF
BACKUP_DIR="$SERVICE_STATE_FIXTURE"
service_was_running router-policy
if service_was_running router-policy-xray; then
  echo "enabled-but-stopped service was misclassified as running" >&2
  exit 1
fi

RESTART_INIT="$TMP/restart-init"
mkdir -p "$RESTART_INIT"
for service in router-policy router-policy-watchdog router-policy-xray router-policy-zapret; do
  cat > "$RESTART_INIT/$service" <<'SH'
#!/bin/sh
printf '%s:%s\n' "${0##*/}" "$1" >> "$SERVICE_SEQUENCE_LOG"
exit 0
SH
  chmod +x "$RESTART_INIT/$service"
done
cat > "$SERVICE_STATE_FIXTURE/install-rollback/services.txt" <<'EOF'
router-policy|1|1
router-policy-watchdog|1|1
router-policy-xray|1|1
router-policy-zapret|1|1
EOF
SERVICE_SEQUENCE_LOG="$TMP/service-sequence.log"
INIT_DIR="$RESTART_INIT"
export SERVICE_SEQUENCE_LOG
wait_control_health() {
  printf 'control:healthy\n' >> "$SERVICE_SEQUENCE_LOG"
}
restart_running_services
grep -Fx 'router-policy:start' "$SERVICE_SEQUENCE_LOG" >/dev/null
grep -Fx 'control:healthy' "$SERVICE_SEQUENCE_LOG" >/dev/null
grep -Fx 'router-policy-watchdog:start' "$SERVICE_SEQUENCE_LOG" >/dev/null
if grep -E '^router-policy-(xray|zapret):restart$' "$SERVICE_SEQUENCE_LOG" >/dev/null; then
  echo "installer restarted production dataplane providers" >&2
  exit 1
fi
controller_line=$(grep -n '^router-policy:start$' "$SERVICE_SEQUENCE_LOG" | cut -d: -f1)
health_line=$(grep -n '^control:healthy$' "$SERVICE_SEQUENCE_LOG" | cut -d: -f1)
watchdog_line=$(grep -n '^router-policy-watchdog:start$' "$SERVICE_SEQUENCE_LOG" | cut -d: -f1)
[ "$controller_line" -lt "$health_line" ] && [ "$health_line" -lt "$watchdog_line" ] || {
  echo "controller/watchdog recovery order is unsafe" >&2
  exit 1
}

ROLLBACK_ROOT="$TMP/rollback-result"
ROLLBACK_TARGET="$ROLLBACK_ROOT/target.txt"
ROLLBACK_BACKUP="$ROLLBACK_ROOT/backup"
ROLLBACK_STAGE="$ROLLBACK_ROOT/stage"
ROLLBACK_INIT="$ROLLBACK_ROOT/init"
mkdir -p "$ROLLBACK_BACKUP/install-rollback" "$ROLLBACK_STAGE/${ROLLBACK_TARGET#/}" "$ROLLBACK_INIT"
rmdir "$ROLLBACK_STAGE/${ROLLBACK_TARGET#/}"
mkdir -p "$ROLLBACK_STAGE/$(dirname "${ROLLBACK_TARGET#/}")"
printf 'original\n' > "$ROLLBACK_STAGE/${ROLLBACK_TARGET#/}"
printf 'changed\n' > "$ROLLBACK_TARGET"
printf 'present|%s\n' "$ROLLBACK_TARGET" > "$ROLLBACK_BACKUP/install-rollback/manifest.txt"
(cd "$ROLLBACK_STAGE" && tar -cf "$ROLLBACK_BACKUP/install-rollback/files.tar" .)
sha256sum "$ROLLBACK_BACKUP/install-rollback/files.tar" | awk '{print $1}' > "$ROLLBACK_BACKUP/install-rollback/files.sha256"
cat > "$ROLLBACK_BACKUP/install-rollback/services.txt" <<'EOF'
router-policy|1|1
router-policy-watchdog|1|1
router-policy-xray|1|1
router-policy-zapret|1|1
EOF
for service in router-policy router-policy-watchdog router-policy-xray router-policy-zapret; do
  cat > "$ROLLBACK_INIT/$service" <<'SH'
#!/bin/sh
if [ "${0##*/}" = "router-policy" ] && [ "$1" = "start" ]; then exit 1; fi
if [ "$1" = "running" ]; then exit 1; fi
exit 0
SH
  chmod +x "$ROLLBACK_INIT/$service"
done
BACKUP_DIR="$ROLLBACK_BACKUP"
INIT_DIR="$ROLLBACK_INIT"
INSTALL_TARGETS="$ROLLBACK_TARGET"
ENABLE_SERVICES="router-policy router-policy-watchdog router-policy-xray router-policy-zapret"
if rollback_output=$(restore_installation 2>&1); then
  echo "rollback reported success after controller restoration failed" >&2
  exit 1
fi
printf '%s\n' "$rollback_output" | grep -F 'install_rollback=files-restored-services-unverified' >/dev/null
if printf '%s\n' "$rollback_output" | grep -Fx 'install_rollback=restored' >/dev/null; then
  echo "rollback emitted a false restored result" >&2
  exit 1
fi
[ "$(cat "$ROLLBACK_TARGET")" = "original" ]

printf 'changed-again\n' > "$ROLLBACK_TARGET"
printf 'present|%s\n' "$TMP/not-owned-by-flintroute" > "$ROLLBACK_BACKUP/install-rollback/manifest.txt"
if unowned_target_output=$(restore_installation 2>&1); then
  echo "rollback accepted an unowned snapshot target" >&2
  exit 1
fi
printf '%s\n' "$unowned_target_output" | grep -F 'unowned snapshot target' >/dev/null
[ "$(cat "$ROLLBACK_TARGET")" = "changed-again" ]
printf 'present|%s\n' "$ROLLBACK_TARGET" > "$ROLLBACK_BACKUP/install-rollback/manifest.txt"

cat > "$ROLLBACK_BACKUP/install-rollback/services.txt" <<'EOF'
router-policy|1|1
router-policy-watchdog|1|1
router-policy-xray|1|1
foreign-service|1|1
EOF
if unowned_service_output=$(restore_installation 2>&1); then
  echo "rollback accepted an unowned service manifest entry" >&2
  exit 1
fi
printf '%s\n' "$unowned_service_output" | grep -F 'unowned service manifest entry' >/dev/null
[ "$(cat "$ROLLBACK_TARGET")" = "changed-again" ]
cat > "$ROLLBACK_BACKUP/install-rollback/services.txt" <<'EOF'
router-policy|1|1
router-policy-watchdog|1|1
router-policy-xray|1|1
router-policy-zapret|1|1
EOF

printf 'corruption\n' >> "$ROLLBACK_BACKUP/install-rollback/files.tar"
if corrupted_output=$(restore_installation 2>&1); then
  echo "rollback accepted a corrupted installation snapshot" >&2
  exit 1
fi
printf '%s\n' "$corrupted_output" | grep -F 'snapshot hash mismatch' >/dev/null
[ "$(cat "$ROLLBACK_TARGET")" = "changed-again" ]

# Rollback must never replay umask-created staging parents onto the OpenWrt
# tree.  This reproduces the historical failure with a mock root whose
# critical directories all start at 0755.
PERM_ROOT="$TMP/permission-root"
PERM_BACKUP="$TMP/permission-backup"
mkdir -p "$PERM_ROOT/etc/init.d" "$PERM_ROOT/etc/hotplug.d" "$PERM_ROOT/usr/bin" "$PERM_ROOT/usr/lib/router-policy"
for directory in "$PERM_ROOT" "$PERM_ROOT/etc" "$PERM_ROOT/usr" "$PERM_ROOT/usr/bin" "$PERM_ROOT/usr/lib" "$PERM_ROOT/etc/init.d" "$PERM_ROOT/etc/hotplug.d"; do
  chmod 755 "$directory"
done
printf 'old-runtime\n' > "$PERM_ROOT/usr/lib/router-policy/runtime.txt"
chmod 644 "$PERM_ROOT/usr/lib/router-policy/runtime.txt"
SYSTEM_ROOT="$PERM_ROOT"
PREFIX="$PERM_ROOT/usr/lib/router-policy"
ETC_DIR="$PERM_ROOT/etc/router-policy"
STATE_DIR="$ETC_DIR/state"
BACKUP_ROOT="$TMP"
BACKUP_DIR="$PERM_BACKUP"
INSTALL_TARGETS="$PREFIX"
ENABLE_SERVICES="router-policy"
CRITICAL_SYSTEM_DIRS="$PERM_ROOT $PERM_ROOT/etc $PERM_ROOT/usr $PERM_ROOT/usr/bin $PERM_ROOT/usr/lib $PERM_ROOT/etc/init.d $PERM_ROOT/etc/hotplug.d"
snapshot_installation
printf 'new-runtime\n' > "$PERM_ROOT/usr/lib/router-policy/runtime.txt"
chmod 700 "$PERM_ROOT/usr/lib/router-policy/runtime.txt"
# Exercise the same automatic rollback entry point used by a failed install,
# rather than only calling the restore helper directly.
set +e
(INSTALL_ROLLBACK_ARMED=1; install_exit 1) >/dev/null 2>&1
rollback_status=$?
set -e
[ "$rollback_status" -eq 1 ]
[ "$(cat "$PERM_ROOT/usr/lib/router-policy/runtime.txt")" = "old-runtime" ]
for directory in "$PERM_ROOT" "$PERM_ROOT/etc" "$PERM_ROOT/usr" "$PERM_ROOT/usr/bin" "$PERM_ROOT/usr/lib" "$PERM_ROOT/etc/init.d" "$PERM_ROOT/etc/hotplug.d"; do
  (umask 022; [ "$(stat -c '%a' "$directory")" = "755" ]) || { echo "rollback changed critical parent mode: $directory" >&2; exit 1; }
done

UNINSTALL_DEACTIVATE_ROOT="$TMP/uninstall-deactivate"
mkdir -p \
  "$UNINSTALL_DEACTIVATE_ROOT/bin" \
  "$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/config" \
  "$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/ownership" \
  "$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/last-good" \
  "$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/transactions/rev_4_aabbccddeeff/tx_0011223344556677/generated"
cat >"$UNINSTALL_DEACTIVATE_ROOT/bin/router-policy" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >"$UNINSTALL_DEACTIVATE_LOG"
[ "$1" = internal-rollback-ip-state ]
SH
chmod +x "$UNINSTALL_DEACTIVATE_ROOT/bin/router-policy"
cat >"$UNINSTALL_DEACTIVATE_ROOT/bin/uci" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>"$UNINSTALL_UCI_LOG"
SH
chmod +x "$UNINSTALL_DEACTIVATE_ROOT/bin/uci"
cat >"$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/last-good/transaction.env" <<'EOF'
transaction_id=tx_0011223344556677
revision_id=rev_4_aabbccddeeff
candidate_hash=sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
EOF
cat >"$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/ownership/flow-offloading.env" <<'EOF'
schema_version=1
software=1
hardware=1
recorded_at=2026-07-27T00:00:00Z
EOF
chmod 600 "$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/ownership/flow-offloading.env"
printf '{}\n' >"$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/transactions/rev_4_aabbccddeeff/tx_0011223344556677/generated/ip-plan.json"
UNINSTALL_DEACTIVATE_LOG="$UNINSTALL_DEACTIVATE_ROOT/deactivate.log"
UNINSTALL_UCI_LOG="$UNINSTALL_DEACTIVATE_ROOT/uci.log"
export UNINSTALL_DEACTIVATE_LOG UNINSTALL_UCI_LOG
UNINSTALL_DEACTIVATE_HELPER="$TMP/run-uninstall-deactivate.sh"
cat >"$UNINSTALL_DEACTIVATE_HELPER" <<'SH'
#!/bin/sh
set -eu
. "$PROJECT_ROOT/uninstall.sh"
deactivate_committed_dataplane >"$RESULT_PATH"
SH
chmod +x "$UNINSTALL_DEACTIVATE_HELPER"
env \
  ROUTER_POLICY_UNINSTALL_LIB_ONLY=1 \
  SYSTEM_ROOT="$UNINSTALL_DEACTIVATE_ROOT" \
  ETC_DIR="$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy" \
  STATE_DIR="$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state" \
  RUNTIME_DIR="$UNINSTALL_DEACTIVATE_ROOT/tmp/router-policy" \
  BIN_DIR="$UNINSTALL_DEACTIVATE_ROOT/bin" \
  UCI_BIN="$UNINSTALL_DEACTIVATE_ROOT/bin/uci" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  RESULT_PATH="$UNINSTALL_DEACTIVATE_ROOT/result.txt" \
  sh "$UNINSTALL_DEACTIVATE_HELPER"
grep -Fx 'dataplane_deactivation=verified' "$UNINSTALL_DEACTIVATE_ROOT/result.txt" >/dev/null
grep -Fx 'flow_offloading_restore=persistent-baseline-restored' "$UNINSTALL_DEACTIVATE_ROOT/result.txt" >/dev/null
grep -Fx 'flow_offloading_runtime_reload=deferred' "$UNINSTALL_DEACTIVATE_ROOT/result.txt" >/dev/null
[ ! -e "$UNINSTALL_DEACTIVATE_ROOT/tmp/router-policy/uninstall-empty-ip-state.json" ]
grep -F 'internal-rollback-ip-state --plan ' "$UNINSTALL_DEACTIVATE_LOG" >/dev/null
grep -F -- '--transaction tx_0011223344556677' "$UNINSTALL_DEACTIVATE_LOG" >/dev/null
grep -F -- '--revision rev_4_aabbccddeeff' "$UNINSTALL_DEACTIVATE_LOG" >/dev/null
grep -F -- '--candidate-hash sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' "$UNINSTALL_DEACTIVATE_LOG" >/dev/null
grep -Fx 'set firewall.@defaults[0].flow_offloading=1' "$UNINSTALL_UCI_LOG" >/dev/null
grep -Fx 'set firewall.@defaults[0].flow_offloading_hw=1' "$UNINSTALL_UCI_LOG" >/dev/null
grep -Fx 'commit firewall' "$UNINSTALL_UCI_LOG" >/dev/null

UNINSTALL_NO_LAST_GOOD_ROOT="$TMP/uninstall-no-last-good"
mkdir -p "$UNINSTALL_NO_LAST_GOOD_ROOT/etc/router-policy/state/ownership"
cp "$UNINSTALL_DEACTIVATE_ROOT/etc/router-policy/state/ownership/flow-offloading.env" \
  "$UNINSTALL_NO_LAST_GOOD_ROOT/etc/router-policy/state/ownership/flow-offloading.env"
chmod 600 "$UNINSTALL_NO_LAST_GOOD_ROOT/etc/router-policy/state/ownership/flow-offloading.env"
: >"$UNINSTALL_UCI_LOG"
env \
  ROUTER_POLICY_UNINSTALL_LIB_ONLY=1 \
  SYSTEM_ROOT="$UNINSTALL_NO_LAST_GOOD_ROOT" \
  ETC_DIR="$UNINSTALL_NO_LAST_GOOD_ROOT/etc/router-policy" \
  STATE_DIR="$UNINSTALL_NO_LAST_GOOD_ROOT/etc/router-policy/state" \
  RUNTIME_DIR="$UNINSTALL_NO_LAST_GOOD_ROOT/tmp/router-policy" \
  BIN_DIR="$UNINSTALL_DEACTIVATE_ROOT/bin" \
  UCI_BIN="$UNINSTALL_DEACTIVATE_ROOT/bin/uci" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  RESULT_PATH="$UNINSTALL_NO_LAST_GOOD_ROOT/result.txt" \
  sh "$UNINSTALL_DEACTIVATE_HELPER"
grep -Fx 'flow_offloading_restore=persistent-baseline-restored' "$UNINSTALL_NO_LAST_GOOD_ROOT/result.txt" >/dev/null
grep -Fx 'dataplane_deactivation=verified-empty' "$UNINSTALL_NO_LAST_GOOD_ROOT/result.txt" >/dev/null
grep -Fx 'commit firewall' "$UNINSTALL_UCI_LOG" >/dev/null

UNINSTALL_MISSING_BINDING_ROOT="$TMP/uninstall-missing-binding"
mkdir -p "$UNINSTALL_MISSING_BINDING_ROOT/etc/router-policy/state/transactions/rev_orphan"
: >"$UNINSTALL_MISSING_BINDING_ROOT/etc/router-policy/state/transactions/rev_orphan/status.env"
set +e
env \
  ROUTER_POLICY_UNINSTALL_LIB_ONLY=1 \
  SYSTEM_ROOT="$UNINSTALL_MISSING_BINDING_ROOT" \
  ETC_DIR="$UNINSTALL_MISSING_BINDING_ROOT/etc/router-policy" \
  STATE_DIR="$UNINSTALL_MISSING_BINDING_ROOT/etc/router-policy/state" \
  RUNTIME_DIR="$UNINSTALL_MISSING_BINDING_ROOT/tmp/router-policy" \
  BIN_DIR="$UNINSTALL_DEACTIVATE_ROOT/bin" \
  UCI_BIN="$UNINSTALL_DEACTIVATE_ROOT/bin/uci" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  RESULT_PATH="$UNINSTALL_MISSING_BINDING_ROOT/result.txt" \
  sh "$UNINSTALL_DEACTIVATE_HELPER" >"$UNINSTALL_MISSING_BINDING_ROOT/stdout.txt" 2>"$UNINSTALL_MISSING_BINDING_ROOT/stderr.txt"
missing_binding_status=$?
set -e
[ "$missing_binding_status" -ne 0 ]
grep -F 'committed transaction binding is missing while transaction journals remain' \
  "$UNINSTALL_MISSING_BINDING_ROOT/stderr.txt" >/dev/null

UNINSTALL_DNS_READY_ROOT="$TMP/uninstall-dns-ready"
mkdir -p "$UNINSTALL_DNS_READY_ROOT/bin"
cat >"$UNINSTALL_DNS_READY_ROOT/bin/pidof" <<'SH'
#!/bin/sh
[ "$1" = dnsmasq ]
SH
chmod +x "$UNINSTALL_DNS_READY_ROOT/bin/pidof"
cat >"$UNINSTALL_DNS_READY_ROOT/bin/nslookup" <<'SH'
#!/bin/sh
count=0
[ ! -f "$UNINSTALL_DNS_READY_COUNTER" ] || count="$(cat "$UNINSTALL_DNS_READY_COUNTER")"
count=$((count + 1))
printf '%s\n' "$count" >"$UNINSTALL_DNS_READY_COUNTER"
[ "$count" -ge 3 ]
SH
chmod +x "$UNINSTALL_DNS_READY_ROOT/bin/nslookup"
cat >"$UNINSTALL_DNS_READY_ROOT/bin/sleep" <<'SH'
#!/bin/sh
:
SH
chmod +x "$UNINSTALL_DNS_READY_ROOT/bin/sleep"
UNINSTALL_DNS_READY_COUNTER="$UNINSTALL_DNS_READY_ROOT/attempts"
export UNINSTALL_DNS_READY_COUNTER
(
  ROUTER_POLICY_UNINSTALL_LIB_ONLY=1
  PIDOF_BIN="$UNINSTALL_DNS_READY_ROOT/bin/pidof"
  NSLOOKUP_BIN="$UNINSTALL_DNS_READY_ROOT/bin/nslookup"
  SLEEP_BIN="$UNINSTALL_DNS_READY_ROOT/bin/sleep"
  export ROUTER_POLICY_UNINSTALL_LIB_ONLY PIDOF_BIN NSLOOKUP_BIN SLEEP_BIN
  # shellcheck source=uninstall.sh
  . "$PROJECT_ROOT/uninstall.sh"
  wait_dnsmasq_ready
)
[ "$(cat "$UNINSTALL_DNS_READY_COUNTER")" = 3 ]

# A missing critical OpenWrt parent is not a reason to create it under
# umask 077. Preflight must stop and leave recovery to the operator.
MISSING_ROOT="$TMP/missing-critical-root"
mkdir -p "$MISSING_ROOT/etc" "$MISSING_ROOT/usr"
chmod 755 "$MISSING_ROOT" "$MISSING_ROOT/etc" "$MISSING_ROOT/usr"
SYSTEM_ROOT="$MISSING_ROOT"
CRITICAL_SYSTEM_DIRS="$SYSTEM_ROOT $SYSTEM_ROOT/etc $SYSTEM_ROOT/usr $SYSTEM_ROOT/usr/bin $SYSTEM_ROOT/usr/lib $SYSTEM_ROOT/etc/init.d $SYSTEM_ROOT/etc/hotplug.d"
if validate_critical_system_dirs >/dev/null 2>&1; then
  echo "preflight accepted missing critical system directory" >&2
  exit 1
fi
echo "installer_blocks_missing_critical_parent=true"

# Environment overrides and snapshot manifests must not be able to smuggle
# lexical traversal/ambiguous paths through the ownership allowlist.  The
# kernel would resolve these to a different parent during rm/copy/restore.
for unsafe_path in \
  "$SYSTEM_ROOT/usr/lib/router-policy/../escape" \
  "$SYSTEM_ROOT/etc/./router-policy" \
  "$SYSTEM_ROOT/usr//lib/router-policy" \
  "$SYSTEM_ROOT/etc/router-policy/"; do
  if validate_no_symlink_path "$unsafe_path" >/dev/null 2>&1; then
    echo "installer accepted unsafe lexical path: $unsafe_path" >&2
    exit 1
  fi
done
echo "installer_rejects_lexical_path_traversal=true"

echo "installer_clean_install=true"
echo "installer_idempotent_upgrade=true"
echo "installer_preserves_managed_component_runtime=true"
echo "installer_compatible_downgrade=true"
echo "installer_failed_upgrade_rollback=true"
echo "installer_verified_uninstall=true"
echo "installer_waits_for_control_health=true"
echo "installer_rejects_degraded_health=true"
echo "installer_binds_upgrade_health_to_revision=true"
echo "installer_checks_transaction_dependencies=true"
echo "installer_uses_portable_mode_check=true"
echo "installer_blocks_running_legacy_controller=true"
echo "installer_blocks_unavailable_ubus=true"
echo "installer_preserves_dataplane_provider_processes=true"
echo "installer_reports_partial_rollback=true"
echo "installer_verifies_rollback_snapshot=true"
echo "installer_rejects_unowned_snapshot_metadata=true"
echo "uninstaller_avoids_global_firewall_reload=true"
echo "uninstaller_removes_bound_ip_plan=true"
echo "uninstaller_restores_owned_flow_offloading_baseline=true"
echo "uninstaller_restores_flow_baseline_without_last_good=true"
echo "uninstaller_restricts_recursive_delete_roots=true"
echo "uninstaller_waits_for_dnsmasq_readiness=true"
