#!/bin/sh
set -eu

file="${1:-}"

if [ -z "$file" ] || [ ! -f "$file" ]; then
  echo "usage: validate-subscription.sh SUBSCRIPTION_JSON" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

jq -e '
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
  |
  (type == "object" or type == "array")
  and ($outbounds | type == "array")
  and ([$outbounds[] | select(.protocol == "vless")] | length > 0)
  and all($outbounds[] | select(.protocol == "vless");
    (.tag | type == "string" and length > 0)
    and (.settings.vnext | type == "array" and length > 0)
    and (.settings.vnext[0].address | type == "string" and length > 0)
    and (.settings.vnext[0].port | type == "number")
    and (.settings.vnext[0].users | type == "array" and length > 0)
    and (.settings.vnext[0].users[0].id | type == "string" and length > 0)
    and (.settings.vnext[0].users[0].flow // "" | tostring | test("xtls-rprx-vision|^$"))
    and (.streamSettings | type == "object")
  )
' "$file" >/dev/null

jq -r '
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
  | [$outbounds[] | select(.protocol == "vless")]
  | "valid=true vless_count=\(length)"
' "$file"
