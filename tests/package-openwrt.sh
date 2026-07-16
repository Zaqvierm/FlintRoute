#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
ARCHIVE="$ROOT/dist/flintroute-openwrt-arm64.tar.gz"
TMP="${TMPDIR:-/tmp}/flintroute-package-test-$$"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

[ -s "$ARCHIVE" ] || { echo "OpenWrt package is missing" >&2; exit 1; }
mkdir -p "$TMP"
tar -C "$TMP" -xzf "$ARCHIVE"
for path in install.sh uninstall.sh dist/router-policy-linux-arm64 config/default.json openwrt/adapter.sh openwrt/init.d/router-policy SHA256SUMS; do
  [ -f "$TMP/$path" ] || { echo "package is missing $path" >&2; exit 1; }
done
(
  cd "$TMP"
  sha256sum -c SHA256SUMS >/dev/null
)
ROUTER_POLICY_INSTALL_LIB_ONLY=1 sh -c 'script=$1; set --; . "$script"; preflight_install' "$TMP/install.sh" "$TMP/install.sh"
printf '\n' >> "$TMP/config/schema.json"
if ROUTER_POLICY_INSTALL_LIB_ONLY=1 sh -c 'script=$1; set --; . "$script"; preflight_install' "$TMP/install.sh" "$TMP/install.sh" >/dev/null 2>&1; then
  echo "installer accepted a tampered package" >&2
  exit 1
fi
echo "openwrt_package_verified=true"
echo "openwrt_package_tamper_blocked=true"
