#!/usr/bin/env bash
# Offline end-to-end run of the SES bulk adapter: a local Mautic with this plugin sends through the fake SES server
# (Tests/E2E/fake-ses-server.php) instead of AWS. See README.md next to this script.
#
#   run.sh prepare | fake-up | fake-down | seed [count] [domain] | send | status | retry [--now] | sync
#          | verify [--after-retry] [--after-sync] | all [count] [domain] | async | all-async [count] [domain]
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
#   WORKERS        parallel messenger:consume email workers started by async (default: 2)
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
WORKERS="${WORKERS:-2}"

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

# Rewrites messenger_dsn_email in local.php (re-exported with var_export, so comments in it are lost) and clears the cache.
messenger_dsn() {
  "$PHP_BIN" -r '$f = $argv[1]; require $f; $parameters["messenger_dsn_email"] = $argv[2]; file_put_contents($f, "<?php\n\$parameters = ".var_export($parameters, true).";\n");' "$MAUTIC_ROOT/config/local.php" "$1"
  console cache:clear >/dev/null
  echo "messenger_dsn_email is $1"
}

# Messages waiting in the Doctrine queue of the email transport. Symfony 5.4 and 6.4 acknowledge on MySQL by setting
# delivered_at to 9999-12-31 and delete those rows only on a later fetch; Symfony 7 deletes them at once.
queued() {
  "$PHP_BIN" -- "$MAUTIC_ROOT/config/local.php" <<'PHP'
<?php
require $argv[1];
$db = new PDO(sprintf('mysql:host=%s;port=%s;dbname=%s', $parameters['db_host'], ($parameters['db_port'] ?? null) ?: 3306, $parameters['db_name']), $parameters['db_user'], $parameters['db_password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
if (!$db->query("SHOW TABLES LIKE 'messenger_messages'")->fetchColumn()) {
    echo 0;
    exit;
}
echo $db->query("SELECT COUNT(*) FROM messenger_messages WHERE queue_name = 'default' AND (delivered_at IS NULL OR delivered_at < '9999-01-01')")->fetchColumn();
PHP
}

# Production path: mautic:broadcasts:send only queues on Doctrine, then WORKERS messenger:consume processes deserialise
# the messages and call the transport in parallel, sharing the token bucket and the outbox. The trap restores sync://.
async() (
  local workers='' queue limit i pid failed=0
  trap 'kill $workers 2>/dev/null || true; messenger_dsn sync://' EXIT
  trap 'exit 130' INT TERM
  messenger_dsn doctrine://default
  run send
  queue="$(queued)"
  if [ "$queue" -eq 0 ]; then echo "nothing was queued: seed a new email, or check that messenger_dsn_email in $MAUTIC_ROOT/config/local.php takes effect" >&2; return 1; fi
  # Each worker stops after its share of the queue, so the run ends without waiting for the time limit.
  limit=$(( (queue + WORKERS - 1) / WORKERS ))
  echo "$queue message(s) queued; starting $WORKERS worker(s) with --limit=$limit --time-limit=120, logs in $WORK_DIR/messenger-worker-N.log"
  SECONDS=0
  for i in $(seq 1 "$WORKERS"); do
    # exec makes $! the worker's own pid, so the trap can stop it: bash starts background jobs with Ctrl-C ignored.
    (cd "$MAUTIC_ROOT" && exec "$PHP_BIN" -d memory_limit=1G -d max_execution_time=0 bin/console messenger:consume email --time-limit=120 --limit="$limit" -vv) >"$WORK_DIR/messenger-worker-$i.log" 2>&1 &
    workers="$workers $!"
  done
  i=0
  for pid in $workers; do
    i=$((i + 1))
    if wait "$pid"; then echo "worker $i finished"; else echo "worker $i failed with status $?" >&2; failed=1; fi
  done
  workers=''
  queue="$(queued)"
  echo "workers done after ${SECONDS}s, $queue message(s) left in the queue"
  if [ "$failed" -ne 0 ] || [ "$queue" -ne 0 ]; then echo "see the worker logs in $WORK_DIR" >&2; return 1; fi
  run status
  run verify
)

run() {
  local action="${1:-all}" id
  case "$action" in
    prepare|seed|send|status|retry|sync|verify|all|async|all-async) : "${MAUTIC_ROOT:?set MAUTIC_ROOT to the Mautic project root}" ;;
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
    verify)    shift; BATCH="$BATCH" FAKE_SES_RATE="${FAKE_SES_RATE:-80}" php "$HERE/verify.php" "$MAUTIC_ROOT" "$STATE" "$FAKE_LOG" "$@" ;;
    async)     async ;;
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
    all-async)
      run prepare
      fake_up
      run seed "${2:-100}" "${3:-example.test}"
      run async
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
