#!/bin/sh
set -eu

DRY_RUN="${DRY_RUN:-1}"
SECRET_FILE="${SECRET_FILE:-/etc/router-policy/secrets/vpn-subscription-url}"
WORK_DIR="${WORK_DIR:-/tmp/router-policy/subscription}"
MAX_BYTES="${MAX_BYTES:-2097152}"
VALIDATOR="${VALIDATOR:-./scripts/validate-subscription.sh}"
DOWNLOAD_RETRIES="${DOWNLOAD_RETRIES:-3}"

mkdir -p "$WORK_DIR"
umask 077

if [ ! -f "$SECRET_FILE" ]; then
  echo "secret_file_missing=$SECRET_FILE" >&2
  echo "create it with permissions 600; value is never printed" >&2
  exit 2
fi

# shellcheck disable=SC2012
mode="$(ls -l "$SECRET_FILE" | awk '{print $1}')"
case "$mode" in
  *------*) ;;
  *)
    echo "secret_file_permissions_are_not_strict" >&2
    exit 2
    ;;
esac

tmp_body="$WORK_DIR/body.$$"
tmp_head="$WORK_DIR/headers.$$"
url="$(cat "$SECRET_FILE")"

attempt=1
code=""
while [ "$attempt" -le "$DOWNLOAD_RETRIES" ]; do
  rm -f "$tmp_body" "$tmp_head"
  if code="$(
    curl -fsS \
      --location \
      --max-filesize "$MAX_BYTES" \
      --connect-timeout 10 \
      --max-time 45 \
      -D "$tmp_head" \
      -o "$tmp_body" \
      -w '%{http_code}' \
      "$url"
  )"; then
    break
  fi
  echo "download_attempt_failed=$attempt" >&2
  attempt=$((attempt + 1))
  sleep "$attempt"
done

if [ -z "$code" ]; then
  rm -f "$tmp_body" "$tmp_head"
  echo "download_failed_after_retries" >&2
  exit 1
fi

if [ "$code" != "200" ]; then
  rm -f "$tmp_body" "$tmp_head"
  echo "download_http_status=$code" >&2
  exit 1
fi

bytes="$(wc -c < "$tmp_body" | tr -d ' ')"
if [ "$bytes" -le 10 ] || [ "$bytes" -gt "$MAX_BYTES" ]; then
  rm -f "$tmp_body" "$tmp_head"
  echo "download_size_invalid=$bytes" >&2
  exit 1
fi

"$VALIDATOR" "$tmp_body" >/dev/null

if command -v xray >/dev/null 2>&1; then
  xray_candidate="$WORK_DIR/xray-candidate.$$"
  jq '
    if type == "object" and (.outbounds | type == "array") then
      .
    elif type == "array" and any(.[]; type == "object" and (.outbounds | type == "array")) then
      .[0]
    elif type == "array" then
      {outbounds: .}
    else
      .
    end
  ' "$tmp_body" > "$xray_candidate"

  xray run -test -c "$xray_candidate" >/dev/null 2>"$WORK_DIR/xray-test.err" || {
    rm -f "$tmp_body" "$tmp_head"
    rm -f "$xray_candidate"
    echo "xray_test_failed" >&2
    exit 1
  }
  rm -f "$xray_candidate"
else
  echo "xray_missing_skipping_config_test=true"
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "dry_run=true"
  echo "validated_bytes=$bytes"
  rm -f "$tmp_body" "$tmp_head"
  exit 0
fi

echo "refusing_apply_without_separate_implementation" >&2
rm -f "$tmp_body" "$tmp_head"
exit 3
