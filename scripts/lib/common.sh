#!/bin/sh

rp_die() {
  echo "router-policy: $*" >&2
  exit 1
}

rp_warn() {
  echo "router-policy warning: $*" >&2
}

rp_info() {
  echo "router-policy: $*"
}

rp_need() {
  command -v "$1" >/dev/null 2>&1 || rp_die "missing required command: $1"
}

rp_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

rp_repo_root() {
  if [ -n "${ROUTER_POLICY_ROOT:-}" ]; then
    printf '%s\n' "$ROUTER_POLICY_ROOT"
    return
  fi
  here=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." 2>/dev/null && pwd) || here="."
  printf '%s\n' "$here"
}

rp_default_config() {
  if [ -n "${ROUTER_POLICY_CONFIG:-}" ]; then
    printf '%s\n' "$ROUTER_POLICY_CONFIG"
  elif [ -f "/etc/router-policy/config/default.json" ]; then
    printf '%s\n' "/etc/router-policy/config/default.json"
  else
    root=$(rp_repo_root)
    printf '%s\n' "$root/config/default.json"
  fi
}

rp_runtime_dir() {
  config="${1:-$(rp_default_config)}"
  if command -v jq >/dev/null 2>&1 && [ -f "$config" ]; then
    jq -r '.storage.runtime_dir // "/tmp/router-policy"' "$config"
  else
    printf '%s\n' "/tmp/router-policy"
  fi
}

rp_state_dir() {
  config="${1:-$(rp_default_config)}"
  if command -v jq >/dev/null 2>&1 && [ -f "$config" ]; then
    jq -r '.storage.state_dir // "/var/lib/router-policy"' "$config"
  else
    printf '%s\n' "/var/lib/router-policy"
  fi
}

rp_lock() {
  lock="$1"
  shift
  mkdir -p "$(dirname "$lock")"
  (
    flock -n 9 || exit 75
    "$@"
  ) 9>"$lock"
}

rp_atomic_write() {
  target="$1"
  tmp="${target}.$$"
  cat > "$tmp"
  chmod "${RP_ATOMIC_MODE:-600}" "$tmp" 2>/dev/null || true
  mv "$tmp" "$target"
}

rp_redact() {
  sed -E 's/(uuid|id|password|token|shortId|publicKey|privateKey|subscription|url)[=:][^ ]+/\1=REDACTED/Ig'
}
