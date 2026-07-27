#!/bin/sh
set -eu

RUN_DIR="${1:-}"
case "$RUN_DIR" in
  /tmp/router-policy/p14-hardware/p14-lifecycle-*) ;;
  *) echo "unsafe P14 run directory" >&2; exit 64 ;;
esac

chmod 700 "$RUN_DIR/router-policy" "$RUN_DIR/p14-lifecycle-runner.sh"
setsid "$RUN_DIR/p14-lifecycle-runner.sh" "$RUN_DIR" "$RUN_DIR/router-policy" /etc/router-policy/config/default.json >"$RUN_DIR/runner.log" 2>&1 </dev/null &
printf '%s\n' "$!" > "$RUN_DIR/runner.pid"
