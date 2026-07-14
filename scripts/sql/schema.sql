pragma journal_mode = wal;
pragma synchronous = normal;

create table if not exists services (
  name text primary key,
  category text not null,
  config_json text not null,
  updated_at text not null default current_timestamp
);

create table if not exists routes (
  tag text primary key,
  type text not null,
  config_json text not null,
  updated_at text not null default current_timestamp
);

create table if not exists probe_results (
  id integer primary key autoincrement,
  domain text not null,
  service text not null,
  route text not null,
  route_type text not null,
  status text not null,
  latency_ms integer,
  checked_at text not null,
  result_json text not null
);

create index if not exists idx_probe_results_lookup
on probe_results(domain, service, route, checked_at);

create table if not exists selected_routes (
  service text not null,
  domain text not null default '',
  route text not null,
  route_type text not null,
  status text not null,
  selected_at text not null,
  hold_until text,
  result_json text not null,
  primary key(service, domain)
);

create table if not exists counters (
  key text primary key,
  fail_count integer not null default 0,
  success_count integer not null default 0,
  updated_at text not null
);

create table if not exists events (
  id integer primary key autoincrement,
  created_at text not null,
  type text not null,
  service text,
  message text not null,
  dedupe_key text,
  repeated integer not null default 0
);

create table if not exists notifications (
  id integer primary key autoincrement,
  created_at text not null,
  status text not null,
  channel text not null,
  event_type text not null,
  service text,
  message text not null,
  dedupe_key text
);

