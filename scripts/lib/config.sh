#!/bin/sh

rp_config_validate() {
  config="$1"
  rp_need jq
  [ -f "$config" ] || rp_die "config not found: $config"

  jq -e '
    type == "object"
    and (.version >= 2)
    and (.routes | type == "array" and length > 0)
    and (.services | type == "object")
    and all(.routes[]; (.type | type == "string") and (.tag | type == "string" and length > 0))
    and all(.services | to_entries[]; 
      (.value.category | type == "string")
      and (.value.domains | type == "array" and length > 0)
      and (.value.allowed_paths | type == "array" and length > 0)
      and (.value.probe_urls | type == "array" and length > 0)
      and all(.value.probe_urls[];
        (.name | type == "string")
        and (.url | test("^https?://"))
        and (.required | type == "boolean")
        and (.expected_codes | type == "array" and length > 0)
        and (.body_mode | IN("required", "optional", "empty", "ignored"))
      )
    )
  ' "$config" >/dev/null
}

rp_service_for_domain() {
  config="$1"
  domain="$2"
  jq -r --arg domain "$domain" '
    .services
    | to_entries[]
    | select(any(.value.domains[]; $domain == . or ($domain | endswith("." + .))))
    | .key
  ' "$config" | head -n 1
}

rp_service_category() {
  config="$1"
  service="$2"
  jq -r --arg service "$service" '.services[$service].category // "UNKNOWN"' "$config"
}

rp_route_by_tag() {
  config="$1"
  tag="$2"
  jq -c --arg tag "$tag" '.routes[] | select(.tag == $tag)' "$config"
}

rp_route_file_by_tag() {
  config="$1"
  tag="$2"
  runtime_dir="$(rp_runtime_dir "$config")"
  mkdir -p "$runtime_dir/routes"
  file="$runtime_dir/routes/$tag.json"
  rp_route_by_tag "$config" "$tag" > "$file"
  [ -s "$file" ] || rp_die "route not found: $tag"
  printf '%s\n' "$file"
}

