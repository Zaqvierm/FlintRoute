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
chmod +x "$TMP/bin/id" "$TMP/bin/chown"

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
export ROUTER_POLICY_INSTALL_LIB_ONLY=1
export ROUTER_POLICY_SYSTEM_ROOT=""
export ETC_DIR="$TMP/etc/router-policy"
export STATE_DIR="$TMP/etc/router-policy/state"
export RUNTIME_DIR="$TMP/tmp/router-policy"
export PREFIX="$TMP/prefix"

# shellcheck source=../install.sh
. "$ROOT/install.sh"
prepare_controller_identity

grep -F "$TMP/etc/router-policy/secrets" "$CHOWN_LOG" >/dev/null
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
