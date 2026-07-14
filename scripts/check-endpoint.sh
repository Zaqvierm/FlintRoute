#!/bin/sh
set -eu

host="${1:-}"
port="${2:-443}"
timeout_s="${TIMEOUT_SECONDS:-8}"

if [ -z "$host" ]; then
  echo "usage: check-endpoint.sh HOST [PORT]" >&2
  exit 2
fi

dns_state="UNKNOWN"
tcp_state="UNKNOWN"

if command -v drill >/dev/null 2>&1; then
  drill "$host" >/dev/null 2>&1 && dns_state="OK" || dns_state="FAIL"
elif command -v dig >/dev/null 2>&1; then
  dig "$host" >/dev/null 2>&1 && dns_state="OK" || dns_state="FAIL"
elif command -v nslookup >/dev/null 2>&1; then
  nslookup "$host" >/dev/null 2>&1 && dns_state="OK" || dns_state="FAIL"
else
  dns_state="SKIPPED"
fi

if command -v nc >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_s" nc -z "$host" "$port" >/dev/null 2>&1 && tcp_state="OK" || tcp_state="FAIL"
  else
    nc -z "$host" "$port" >/dev/null 2>&1 && tcp_state="OK" || tcp_state="FAIL"
  fi
else
  tcp_state="SKIPPED"
fi

printf '{"host":"%s","port":%s,"dns":"%s","tcp":"%s"}\n' "$host" "$port" "$dns_state" "$tcp_state"

