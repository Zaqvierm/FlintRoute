#!/bin/sh
set -eu

url="${1:-}"
socks="${SOCKS_PROXY:-}"
timeout_s="${TIMEOUT_SECONDS:-15}"

if [ -z "$url" ]; then
  echo "usage: check-service.sh URL" >&2
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 2
fi

proxy_args=""
if [ -n "$socks" ]; then
  proxy_args="--socks5-hostname $socks"
fi

# shellcheck disable=SC2086
curl -sS $proxy_args \
  --connect-timeout 8 \
  --max-time "$timeout_s" \
  -o /dev/null \
  -w '{"url":"%{url_effective}","http_code":%{http_code},"time_total":%{time_total},"remote_ip":"%{remote_ip}"}\n' \
  "$url"

