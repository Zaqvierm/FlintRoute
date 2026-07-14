#!/bin/sh
set -eu

services_file="${1:-config/services.example.json}"
health_file="${2:-tests/sample-health.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

jq -n \
  --slurpfile services "$services_file" \
  --slurpfile health "$health_file" '
  def service_path($svc):
    if $svc.category == "GEO_LOCKED" then
      ["smart_dns", "vless", "drop"]
    elif $svc.category == "TSPU_RESTRICTED" then
      ["zapret", "smart_dns", "vless", "drop"]
    elif $svc.category == "TELEGRAM" then
      ["tg_ws_proxy", "vless", "drop"]
    elif $svc.category == "DIRECT_ONLY" then
      ["direct"]
    elif $svc.category == "BLOCKED" then
      ["drop"]
    else
      ["direct", "zapret", "smart_dns", "vless"]
    end;

  def path_rank($svc; $path):
    service_path($svc) as $paths
    | ($paths | to_entries[] | select(.value == $path) | .key) // 999;

  def state_rank($state):
    if $state == "OK" then 0
    elif $state == "DEGRADED" then 1
    else 9
    end;

  def usable($service_name; $svc; $path):
    ($health[0].services[$service_name].paths[$path] // null) as $p
    | if $path == "drop" then
        {path:"drop", state:"OK", latency_ms:null, reason:"fail_closed", path_rank:(path_rank($svc; $path)), state_rank:8}
      elif $p == null then
        empty
      elif ($p.state == "OK" or $p.state == "DEGRADED") then
        if ($svc.require_non_ru_egress == true and ($p.egress_country // "") == "RU") then
          empty
        else
          $p + {path:$path, path_rank:(path_rank($svc; $path)), state_rank:(state_rank($p.state))}
        end
      else
        empty
      end;

  $services[0].services
  | to_entries
  | map(
      .key as $name
      | .value as $svc
      | [service_path($svc)[] | usable($name; $svc; .)] as $candidates
      | {
          service: $name,
          category: $svc.category,
          selected: (
            if ($candidates | length) == 0 then
              {path:"drop", reason:"no_candidate"}
            else
              ($candidates | sort_by(.state_rank, .path_rank, (.latency_ms // 999999)) | .[0])
            end
          ),
          dry_run: true
        }
    )
' 
