#!/bin/sh
set -eu

domain="${1:-}"
service="${2:-}"
route_tag="${3:-}"
config="${4:-${ROUTER_POLICY_CONFIG:-/etc/router-policy/config/default.json}}"
router_policy_bin="${ROUTER_POLICY_BIN:-/usr/bin/router-policy}"

[ -n "$domain" ] && [ -n "$service" ] && [ -n "$route_tag" ] || {
  echo "usage: probe-route.sh DOMAIN SERVICE ROUTE_TAG [CONFIG]" >&2
  exit 2
}

ROUTER_POLICY_CONFIG="$config" exec "$router_policy_bin" probe-route --route "$route_tag" "$domain" "$service"
