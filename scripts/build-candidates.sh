#!/bin/sh
set -eu

domain="${1:-}"
service="${2:-}"
tspu_match="${3:-false}"
services_file="${SERVICES_FILE:-config/services.example.json}"
routes_file="${ROUTES_FILE:-config/routes.example.json}"

if [ -z "$domain" ] || [ -z "$service" ]; then
  echo "usage: build-candidates.sh DOMAIN SERVICE [tspu_match:true|false]" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

jq -n \
  --arg domain "$domain" \
  --arg service "$service" \
  --argjson tspu_match "$tspu_match" \
  --slurpfile services "$services_file" \
  --slurpfile routes "$routes_file" '
  def route_by_type($type):
    $routes[0].routes[] | select(.type == $type);

  def vless_routes:
    $routes[0].routes[] | select(.type == "vless");

  def service_category:
    $services[0].services[$service].category // "UNKNOWN";

  def candidate_types:
    if service_category == "DIRECT_ONLY" then
      ["direct"]
    elif service_category == "GEO_LOCKED" then
      ["smart_dns", "vless"]
    elif service_category == "TELEGRAM" then
      ["tg_ws_proxy", "vless"]
    elif service_category == "TSPU_RESTRICTED" then
      ["zapret", "smart_dns", "vless"]
    elif service_category == "BLOCKED" then
      ["drop"]
    elif service_category == "UNKNOWN" then
      if $tspu_match then ["zapret", "smart_dns", "vless"] else ["direct"] end
    else
      ["direct", "zapret", "smart_dns", "vless"]
    end;

  {
    domain: $domain,
    service: $service,
    category: service_category,
    tspu_match: $tspu_match,
    candidates: [
      candidate_types[] as $type
      | if $type == "vless" then vless_routes
        elif $type == "drop" then {type:"drop", tag:"drop"}
        else route_by_type($type)
        end
    ]
  }'

