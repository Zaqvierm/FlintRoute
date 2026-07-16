#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$ROOT/dist"
STAGING="$DIST/.flintroute-openwrt-arm64"
ARCHIVE="$DIST/flintroute-openwrt-arm64.tar.gz"
BINARY="$DIST/router-policy-linux-arm64"
FILE_LIST="$DIST/.flintroute-package-files.$$"
trap 'rm -rf "$STAGING"; rm -f "$FILE_LIST" "$ARCHIVE.tmp"' EXIT HUP INT TERM

[ -f "$BINARY" ] || { echo "missing $BINARY; build the ARM64 binary first" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }

rm -rf "$STAGING"
mkdir -p "$STAGING/dist"
cp "$ROOT/install.sh" "$ROOT/uninstall.sh" "$ROOT/LICENSE" "$ROOT/NOTICE" "$STAGING/"
cp -R "$ROOT/config" "$ROOT/openwrt" "$ROOT/scripts" "$STAGING/"
cp "$BINARY" "$STAGING/dist/router-policy-linux-arm64"
chmod +x "$STAGING/install.sh" "$STAGING/uninstall.sh" "$STAGING/dist/router-policy-linux-arm64"

(
  cd "$STAGING"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort > "$FILE_LIST"
  while IFS= read -r path; do
    sha256sum "$path"
  done < "$FILE_LIST" > SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)

tar -C "$STAGING" -czf "$ARCHIVE.tmp" .
mv "$ARCHIVE.tmp" "$ARCHIVE"
tar -tzf "$ARCHIVE" >/dev/null
archive_hash=$(sha256sum "$ARCHIVE" | awk '{print $1}')
rm -rf "$STAGING"
rm -f "$FILE_LIST"
trap - EXIT HUP INT TERM

echo "package=$ARCHIVE"
echo "sha256=$archive_hash"
