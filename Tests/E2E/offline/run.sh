#!/usr/bin/env bash
# Offline end-to-end run of the SES bulk adapter: a local Mautic with this plugin sends through the fake SES server
# (Tests/E2E/fake-ses-server.php) instead of AWS. See README.md next to this script.
#
#   run.sh prepare | fake-up | fake-down | seed [count] [domain] | send | status | retry [--now] | sync
#          | verify [--after-retry] [--after-sync] | all [count] [domain]
#
# Environment:
#   PHP_BIN        PHP binary for Mautic and the fake server (default: php)
#   MAUTIC_ROOT    Mautic project root with bin/console, config/local.php and docroot/ (required except for fake-up/fake-down)
#   PLUGIN_ROOT    checkout of this plugin that provides Tests/E2E/fake-ses-server.php (default: the checkout containing this script)
#   FAKE_PORT      fake SES port, must match the endpoint in mailer_dsn (default: 4566)
#   FAKE_LOG       JSONL request log of the fake server (default: <PHP sys_get_temp_dir()>/fake-ses-requests.jsonl);
#                  the pid file and output of the fake server are kept next to it
#   FAKE_SES_RATE  MaxSendRate reported by the fake account endpoint (default: 80)
#   STATE          seed state (email id, contacts) read by send/status/retry/verify (default: ses-e2e-state.json next to FAKE_LOG)
#   BATCH          contacts per mautic:broadcasts:send batch (default: 100)
# Give every Mautic install its own FAKE_PORT, FAKE_LOG and STATE.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_BIN="${PHP_BIN:-php}"
PLUGIN_ROOT="${PLUGIN_ROOT:-$(cd "$HERE/../../.." && pwd)}"
FAKE_PORT="${FAKE_PORT:-4566}"
FAKE_LOG="${FAKE_LOG:-$("$PHP_BIN" -r 'echo sys_get_temp_dir();')/fake-ses-requests.jsonl}"
WORK_DIR="$(dirname "$FAKE_LOG")"
mkdir -p "$WORK_DIR"
FAKE_PID="$WORK_DIR/fake-ses-$FAKE_PORT.pid"
STATE="${STATE:-$WORK_DIR/ses-e2e-state.json}"
BATCH="${BATCH:-100}"

php() { "$PHP_BIN" -d memory_limit=1G -d max_execution_time=0 "$@"; }
console() { (cd "$MAUTIC_ROOT" && php bin/console "$@"); }

email_id() {
  if [ ! -f "$STATE" ]; then echo "no seed state at $STATE: run seed first" >&2; return 1; fi
  "$PHP_BIN" -r 'echo json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR)["email_id"];' "$STATE"
}

fake_up() {
  if [ -f "$FAKE_PID" ] && kill -0 "$(cat "$FAKE_PID")" 2>/dev/null; then
    echo "fake SES already running (pid $(cat "$FAKE_PID"))"; return
  fi
  if curl -s -o /dev/null "http://127.0.0.1:$FAKE_PORT/"; then
    echo "port $FAKE_PORT is already in use by another server; stop it first" >&2; return 1
  fi
  # A fresh server starts with an empty log and forgets which flaky@ addresses it has seen.
  : > "$FAKE_LOG"
  rm -f "$FAKE_LOG.state.json"
  FAKE_SES_LOG="$FAKE_LOG" FAKE_SES_RATE="${FAKE_SES_RATE:-80}" nohup "$PHP_BIN" -S "127.0.0.1:$FAKE_PORT" "$PLUGIN_ROOT/Tests/E2E/fake-ses-server.php" >"$WORK_DIR/fake-ses-$FAKE_PORT.out" 2>&1 &
  echo $! > "$FAKE_PID"
  curl -s --retry 10 --retry-connrefused --retry-delay 1 -o /dev/null "http://127.0.0.1:$FAKE_PORT/v2/email/account"
  echo "fake SES listening on 127.0.0.1:$FAKE_PORT, log $FAKE_LOG"
}

fake_down() {
  if [ -f "$FAKE_PID" ]; then
    pkill -P "$(cat "$FAKE_PID")" 2>/dev/null || true
    kill "$(cat "$FAKE_PID")" 2>/dev/null || true
    rm -f "$FAKE_PID"; echo "fake SES stopped"
  fi
}

# Retry rows become due 60 s, 120 s and 240 s after each failed attempt; --now makes this email's rows due immediately.
retry() {
  case "${1:-}" in
    --now)
      local id prefix
      id="$(email_id)"
      prefix="$("$PHP_BIN" -r 'require $argv[1]; echo $parameters["db_table_prefix"] ?? "";' "$MAUTIC_ROOT/config/local.php")"
      console dbal:run-sql "UPDATE ${prefix}ses_bulk_deliveries SET next_attempt = 0 WHERE email_id = ${id} AND state = 'retry'"
      ;;
    '') ;;
    *) echo "usage: run.sh retry [--now]" >&2; return 2 ;;
  esac
  console mautic:ses:bulk retry --limit=1000
}

run() {
  local action="${1:-all}" id
  case "$action" in
    prepare|seed|send|status|retry|sync|verify|all) : "${MAUTIC_ROOT:?set MAUTIC_ROOT to the Mautic project root}" ;;
  esac
  case "$action" in
    fake-up)   fake_up ;;
    fake-down) fake_down ;;
    prepare)   console cache:clear; console mautic:plugins:reload; console mautic:ses:bulk install ;;
    seed)      STATE_FILE="$STATE" php "$HERE/seed.php" "$MAUTIC_ROOT" "${2:-100}" "${3:-example.test}" ;;
    send)      id="$(email_id)"; console mautic:broadcasts:send --channel=email --id="$id" --limit=100000 --batch="$BATCH" --bypass-locking ;;
    status)    id="$(email_id)"; console mautic:ses:bulk status --email-id="$id" ;;
    retry)     retry "${2:-}" ;;
    sync)      console mautic:ses:bulk sync-stats ;;
    verify)    shift; php "$HERE/verify.php" "$MAUTIC_ROOT" "$STATE" "$FAKE_LOG" "$@" ;;
    all)
      run prepare
      fake_up
      run seed "${2:-100}" "${3:-example.test}"
      run send
      run status
      run verify
      retry --now
      run status
      run verify --after-retry
      run sync
      run verify --after-retry --after-sync
      ;;
    *) echo "unknown action: $action" >&2; return 2 ;;
  esac
}

run "$@"
