#!/bin/sh
set -eu

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

mkdir -p "$TMP/bin" "$TMP/etc/router-policy/config" "$TMP/etc/router-policy/secrets" \
  "$TMP/etc/router-policy/state" "$TMP/tmp/router-policy" "$TMP/prefix"

cat > "$TMP/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}:${2:-}" in
  -u:daemon|-g:daemon) echo 1 ;;
  *) exec /usr/bin/id "$@" ;;
esac
EOF
cat > "$TMP/bin/chown" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CHOWN_LOG"
exit 0
EOF
REAL_CHMOD="$(command -v chmod)"
cat > "$TMP/bin/chmod" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "\$CHMOD_LOG"
exec "$REAL_CHMOD" "\$@"
EOF
chmod +x "$TMP/bin/id" "$TMP/bin/chown" "$TMP/bin/chmod"

for file in default.json schema.json listener.conf helper.env; do
  if [ "$file" = "helper.env" ]; then
    : > "$TMP/etc/router-policy/$file"
  else
    : > "$TMP/etc/router-policy/config/$file"
  fi
done
for file in vpn-subscription-url happ-crypt4-private-key.pem telegram.json webhook.env foreign-secret; do
  : > "$TMP/etc/router-policy/secrets/$file"
done
export PATH="$TMP/bin:$PATH"
export CHOWN_LOG="$TMP/chown.log"
export CHMOD_LOG="$TMP/chmod.log"
export ROUTER_POLICY_INSTALL_LIB_ONLY=1
export ROUTER_POLICY_SYSTEM_ROOT=""
export ETC_DIR="$TMP/etc/router-policy"
export STATE_DIR="$TMP/etc/router-policy/state"
export RUNTIME_DIR="$TMP/tmp/router-policy"
export PREFIX="$TMP/prefix"

# shellcheck disable=SC1091
. "$ROOT/install.sh"
# Git Bash exposes host uid/gid values that are unrelated to the OpenWrt
# daemon/root pair.  Keep this fixture focused on the ownership call set while
# preserving the installer contract that only 0:0 or daemon:daemon entries are
# acceptable on the target platform.
path_metadata() {
  case "$1" in
    "$TMP"/*) printf '755|0|0\n' ;;
    *) return 1 ;;
  esac
}
mkdir -p "$TMP/prefix/components"
: > "$TMP/prefix/components/foreign-runtime"
chmod 700 "$TMP/prefix/components/foreign-runtime"
mkdir -p "$TMP/etc/router-policy/zapret"
: > "$TMP/etc/router-policy/zapret/catalog.json"
chmod 700 "$TMP/etc/router-policy"
component_mode_before=""
if command -v stat >/dev/null 2>&1; then
  component_mode_before="$(stat -c '%a' "$TMP/prefix/components/foreign-runtime" 2>/dev/null || true)"
fi
prepare_controller_identity

# The non-root controller must be able to traverse its exact config root,
# while the root remains owned by root and no recursive ownership operation
# is used.
grep -F -- "750 $TMP/etc/router-policy" "$CHMOD_LOG" >/dev/null || {
  echo "controller config root was not made traversable by daemon" >&2
  exit 1
}
grep -F -- '0:1 ' "$CHOWN_LOG" >/dev/null || {
  echo "controller config root was not assigned root:daemon ownership" >&2
  exit 1
}
grep -F -- "0:1 $TMP/etc/router-policy/zapret" "$CHOWN_LOG" >/dev/null || {
  echo "Zapret metadata root was not assigned root:daemon ownership" >&2
  exit 1
}
grep -F -- "0:1 $TMP/etc/router-policy/zapret/catalog.json" "$CHOWN_LOG" >/dev/null || {
  echo "Zapret catalog was not assigned root:daemon ownership" >&2
  exit 1
}
grep -F -- "750 $TMP/etc/router-policy/zapret" "$CHMOD_LOG" >/dev/null || {
  echo "Zapret metadata root was not made traversable" >&2
  exit 1
}
grep -F -- "660 $TMP/etc/router-policy/zapret/catalog.json" "$CHMOD_LOG" >/dev/null || {
  echo "Zapret catalog was not made writable by daemon" >&2
  exit 1
}

if [ -n "$component_mode_before" ]; then
  component_mode_after="$(stat -c '%a' "$TMP/prefix/components/foreign-runtime" 2>/dev/null || true)"
  [ "$component_mode_after" = "$component_mode_before" ] || {
    echo "preserved component runtime was chmod'ed by controller setup" >&2
    exit 1
  }
fi

grep -F "$TMP/etc/router-policy/secrets" "$CHOWN_LOG" >/dev/null
if grep -F -- '-R' "$CHOWN_LOG" >/dev/null; then
  echo "controller ownership used recursive chown" >&2
  exit 1
fi
for file in vpn-subscription-url happ-crypt4-private-key.pem telegram.json webhook.env; do
  grep -F "$TMP/etc/router-policy/secrets/$file" "$CHOWN_LOG" >/dev/null || {
    echo "managed secret was not assigned: $file" >&2
    exit 1
  }
done
if grep -F "$TMP/etc/router-policy/secrets/foreign-secret" "$CHOWN_LOG" >/dev/null; then
  echo "foreign secret was assigned to the controller" >&2
  exit 1
fi

: > "$TMP/etc/router-policy/config/foreign.conf"
path_metadata() {
  case "$1" in
    "$TMP/etc/router-policy/config/foreign.conf") printf '640|1000|1000\n' ;;
    "$TMP"/*) printf '755|0|0\n' ;;
    *) return 1 ;;
  esac
}
set +e
foreign_output=$(prepare_controller_identity 2>&1)
foreign_rc=$?
set -e
[ "$foreign_rc" -ne 0 ]
printf '%s\n' "$foreign_output" | grep -F 'foreign owner in controller-owned tree' >/dev/null
if grep -F "$TMP/etc/router-policy/config/foreign.conf" "$CHOWN_LOG" >/dev/null; then
  echo "foreign config was assigned to the controller" >&2
  exit 1
fi

mkdir -p "$TMP/foreign-runtime"
if ln -s "$TMP/foreign-runtime" "$TMP/runtime-link" 2>/dev/null && [ -L "$TMP/runtime-link" ]; then
  original_runtime_dir="$RUNTIME_DIR"
  RUNTIME_DIR="$TMP/runtime-link"
  set +e
  runtime_output=$(validate_managed_roots 2>&1)
  runtime_rc=$?
  set -e
  [ "$runtime_rc" -ne 0 ]
  printf '%s\n' "$runtime_output" | grep -F 'managed path contains a symlink' >/dev/null
  RUNTIME_DIR="$original_runtime_dir"
else
  echo "managed_root_symlink_test=skipped-filesystem"
fi

rm -f "$TMP/etc/router-policy/secrets/telegram.json"
if ln -s "$TMP/foreign-secret" "$TMP/etc/router-policy/secrets/telegram.json" 2>/dev/null; then
  set +e
  symlink_output=$(prepare_controller_identity 2>&1)
  symlink_rc=$?
  set -e
  [ "$symlink_rc" -ne 0 ]
  printf '%s\n' "$symlink_output" | grep -F 'managed secret is a symlink' >/dev/null

  # The same rejection must happen at install_files() entry, before the
  # installer can chmod or truncate the symlink target.
  export SYSTEM_ROOT="$TMP"
  export ETC_DIR="$TMP/etc/router-policy"
  export STATE_DIR="$TMP/etc/router-policy/state"
  export RUNTIME_DIR="$TMP/tmp/router-policy"
  export PREFIX="$TMP/usr/lib/router-policy"
  export BIN_DIR="$TMP/usr/bin"
  export INIT_DIR="$TMP/etc/init.d"
  export RC_DIR="$TMP/etc/rc.d"
  export HOTPLUG_IFACE_DIR="$TMP/etc/hotplug.d/iface"
  export HOTPLUG_FIREWALL_DIR="$TMP/etc/hotplug.d/firewall"
  export DNSMASQ_DIR="$TMP/tmp/dnsmasq.d"
  set +e
  install_output=$(install_files 2>&1)
  install_rc=$?
  set -e
  [ "$install_rc" -ne 0 ]
  printf '%s\n' "$install_output" | grep -F 'managed secret is a symlink' >/dev/null
else
  echo "secret_symlink_test=skipped-filesystem"
fi

# The directory itself must be checked again at install_files() entry.  This
# models a path replacement after preflight/snapshot and proves no mkdir or
# subscription-file write follows a foreign secrets symlink.
if ln -s "$TMP/foreign-secret-dir" "$TMP/etc/router-policy/secrets-dir" 2>/dev/null; then
  rm -rf "$TMP/etc/router-policy/secrets"
  ln -s "$TMP/foreign-secret-dir" "$TMP/etc/router-policy/secrets"
  mkdir -p "$TMP/foreign-secret-dir"
  export SYSTEM_ROOT="$TMP"
  export ETC_DIR="$TMP/etc/router-policy"
  export STATE_DIR="$TMP/etc/router-policy/state"
  export RUNTIME_DIR="$TMP/tmp/router-policy"
  export PREFIX="$TMP/usr/lib/router-policy"
  export BIN_DIR="$TMP/usr/bin"
  export INIT_DIR="$TMP/etc/init.d"
  export RC_DIR="$TMP/etc/rc.d"
  export HOTPLUG_IFACE_DIR="$TMP/etc/hotplug.d/iface"
  export HOTPLUG_FIREWALL_DIR="$TMP/etc/hotplug.d/firewall"
  export DNSMASQ_DIR="$TMP/tmp/dnsmasq.d"
  set +e
  install_output=$(install_files 2>&1)
  install_rc=$?
  set -e
  [ "$install_rc" -ne 0 ]
  printf '%s\n' "$install_output" | grep -F 'secrets path contains a symlink' >/dev/null
  [ ! -e "$TMP/foreign-secret-dir/vpn-subscription-url" ]
else
  echo "secret_directory_symlink_test=skipped-filesystem"
fi

echo "installer_secret_ownership_ok=true"
