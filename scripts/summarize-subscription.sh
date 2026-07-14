#!/bin/sh
set -eu

file="${1:-}"

if [ -z "$file" ] || [ ! -f "$file" ]; then
  echo "usage: summarize-subscription.sh SUBSCRIPTION_JSON" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

jq '
  def normalized_outbounds:
    if type == "object" and (.outbounds | type == "array") then
      .outbounds
    elif type == "array" and any(.[]; type == "object" and (.outbounds | type == "array")) then
      [.[] | select(type == "object" and (.outbounds | type == "array")) | .outbounds[]]
    elif type == "array" then
      .
    else
      []
    end;

  normalized_outbounds as $outbounds
  | {
      top_level_type: type,
      config_count: (if type == "array" then length else 1 end),
      outbound_count: ($outbounds | length),
      protocol_counts: (
        reduce $outbounds[] as $o ({}; .[$o.protocol // "null"] += 1)
      ),
      stream_security_counts: (
        reduce $outbounds[] as $o ({}; .[$o.streamSettings.security // "null"] += 1)
      ),
      stream_network_counts: (
        reduce $outbounds[] as $o ({}; .[$o.streamSettings.network // "null"] += 1)
      ),
      vless_count: ([$outbounds[] | select(.protocol == "vless")] | length),
      safe_summary: true
    }
' "$file"
