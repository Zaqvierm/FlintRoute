#!/bin/sh

rp_db_path() {
  config="$1"
  jq -r '.storage.database // "/etc/router-policy/state/router-policy.sqlite"' "$config"
}

rp_db_init() {
  config="$1"
  state_dir="$(rp_state_dir "$config")"
  mkdir -p "$state_dir"
  db="$(rp_db_path "$config")"

  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" < "$(dirname "$0")/../sql/schema.sql"
    echo "db_mode=sqlite path=$db"
  else
    mkdir -p "$state_dir/json"
    : > "$state_dir/json/events.jsonl"
    : > "$state_dir/json/results.jsonl"
    echo "db_mode=jsonl path=$state_dir/json"
  fi
}

rp_db_event() {
  config="$1"
  event_type="$2"
  service="$3"
  message="$4"
  state_dir="$(rp_state_dir "$config")"
  db="$(rp_db_path "$config")"
  now="$(rp_now)"

  if command -v sqlite3 >/dev/null 2>&1 && [ -f "$db" ]; then
    sqlite3 "$db" \
      "insert into events(created_at,type,service,message) values('$now','$(printf "%s" "$event_type" | sed "s/'/''/g")','$(printf "%s" "$service" | sed "s/'/''/g")','$(printf "%s" "$message" | sed "s/'/''/g")');"
  else
    mkdir -p "$state_dir/json"
    jq -n --arg created_at "$now" --arg type "$event_type" --arg service "$service" --arg message "$message" \
      '{created_at:$created_at,type:$type,service:$service,message:$message}' >> "$state_dir/json/events.jsonl"
  fi
}

rp_db_store_result() {
  config="$1"
  result_file="$2"
  state_dir="$(rp_state_dir "$config")"
  db="$(rp_db_path "$config")"

  if command -v sqlite3 >/dev/null 2>&1 && [ -f "$db" ]; then
    domain="$(jq -r '.domain' "$result_file")"
    service="$(jq -r '.service' "$result_file")"
    route="$(jq -r '.route' "$result_file")"
    route_type="$(jq -r '.route_type' "$result_file")"
    status="$(jq -r '.status' "$result_file")"
    latency="$(jq -r '.latency_ms // "NULL"' "$result_file")"
    checked_at="$(jq -r '.checked_at' "$result_file")"
    json="$(jq -c . "$result_file" | sed "s/'/''/g")"
    sqlite3 "$db" "insert into probe_results(domain,service,route,route_type,status,latency_ms,checked_at,result_json) values('$(printf "%s" "$domain" | sed "s/'/''/g")','$(printf "%s" "$service" | sed "s/'/''/g")','$(printf "%s" "$route" | sed "s/'/''/g")','$(printf "%s" "$route_type" | sed "s/'/''/g")','$(printf "%s" "$status" | sed "s/'/''/g")',$latency,'$(printf "%s" "$checked_at" | sed "s/'/''/g")','$json');"
  else
    mkdir -p "$state_dir/json"
    jq -c . "$result_file" >> "$state_dir/json/results.jsonl"
  fi
}
