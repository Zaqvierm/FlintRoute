#!/bin/sh
set -eu

domain="${1:-}"
service="${2:-unknown}"
config="${3:-${ROUTER_POLICY_CONFIG:-/etc/router-policy/config/default.json}}"
router_policy_bin="${ROUTER_POLICY_BIN:-/usr/bin/router-policy}"

[ -n "$domain" ] || {
  echo "usage: check-domain.sh DOMAIN [SERVICE] [CONFIG]" >&2
  exit 2
}

ROUTER_POLICY_CONFIG="$config" exec "$router_policy_bin" check-domain "$domain" "$service"
