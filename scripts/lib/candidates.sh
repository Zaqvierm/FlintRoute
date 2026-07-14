#!/bin/sh

rp_build_candidates() {
  config="$1"
  domain="$2"
  service="$3"
  tspu_match="${4:-false}"

  jq -n \
    --arg domain "$domain" \
    --arg service "$service" \
    --argjson tspu_match "$tspu_match" \
    --slurpfile cfg "$config" '
    def svc: $cfg[0].services[$service] // {
      category: "UNKNOWN",
      allowed_paths: ["direct", "zapret", "smart_dns", "vless"],
      forbidden_paths: [],
      require_non_ru_egress: false
    };

    def service_order:
      if svc.category == "DIRECT_ONLY" then ["direct"]
      elif svc.category == "GEO_LOCKED" then ["smart_dns", "vless", "drop"]
      elif svc.category == "TELEGRAM" then ["tg_ws_proxy", "vless", "drop"]
      elif svc.category == "TSPU_RESTRICTED" then ["zapret", "smart_dns", "vless", "drop"]
      elif svc.category == "BLOCKED" then ["drop"]
      elif svc.category == "UNKNOWN" then
        if $tspu_match then ["zapret", "smart_dns", "vless", "drop"] else ["direct"] end
      else ["direct", "zapret", "smart_dns", "vless"]
      end;

    def allowed($r):
      ((svc.allowed_paths // []) | index($r.type)) != null
      and (((svc.forbidden_paths // []) | index($r.type)) == null)
      and (
        if svc.category == "GEO_LOCKED" then ($r.type != "direct" and $r.type != "zapret")
        elif svc.category == "DIRECT_ONLY" then $r.type == "direct"
        else true end
      );

    def routes_for_type($type):
      if $type == "vless" then
        $cfg[0].routes[] | select(.type == "vless")
      elif $type == "drop" then
        {type:"drop", tag:"drop", priority:999}
      else
        $cfg[0].routes[] | select(.type == $type)
      end;

    {
      domain: $domain,
      service: $service,
      category: svc.category,
      candidates: [
        service_order[] as $type
        | routes_for_type($type)
        | select(allowed(.))
      ]
    }'
}

