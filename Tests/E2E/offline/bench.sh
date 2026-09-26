#!/usr/bin/env bash
# Benchmark bulk=auto against bulk=off on the same local Mautic with the fake SES server. See README.md next to this script.
#
#   bench.sh <auto|off> <count> [html-file]
#
# Uses the run.sh environment (PHP_BIN, MAUTIC_ROOT, PLUGIN_ROOT, FAKE_PORT, FAKE_LOG, STATE). Extra knobs:
#   RATELIMIT          DSN ratelimit for the run (default 100000 = no throttling, measures local resources)
#   BULK_CONC          bulk_concurrency for auto runs (default 2)
#   BATCH              contacts per mautic:broadcasts:send batch (default 500)
#   FAKE_SES_DELAY_MS  artificial latency per fake SES request (default 0)
#   FAKE_WORKERS       PHP built-in server workers for the fake SES (default 16)
#   RESULTS            TSV file that gets one line per run (default: bench-results.tsv next to FAKE_LOG)
# Rewrites mailer_dsn in <MAUTIC_ROOT>/config/local.php and leaves the fake SES server running (run.sh fake-down stops it).
set -euo pipefail

MODE="${1:?auto|off}"; COUNT="${2:?count}"; HTML="${3:-}"
case "$MODE" in auto|off) ;; *) echo "usage: bench.sh <auto|off> <count> [html-file]" >&2; exit 2 ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_BIN="${PHP_BIN:-php}"
MAUTIC_ROOT="${MAUTIC_ROOT:?set MAUTIC_ROOT to the Mautic project root}"
PLUGIN_ROOT="${PLUGIN_ROOT:-$(cd "$HERE/../../.." && pwd)}"
FAKE_PORT="${FAKE_PORT:-4566}"
FAKE_LOG="${FAKE_LOG:-$("$PHP_BIN" -r 'echo sys_get_temp_dir();')/fake-ses-requests.jsonl}"
WORK_DIR="$(dirname "$FAKE_LOG")"
mkdir -p "$WORK_DIR"
STATE="${STATE:-$WORK_DIR/ses-e2e-state.json}"
RATELIMIT="${RATELIMIT:-100000}"
BULK_CONC="${BULK_CONC:-2}"
BATCH="${BATCH:-500}"
FAKE_SES_DELAY_MS="${FAKE_SES_DELAY_MS:-0}"
FAKE_WORKERS="${FAKE_WORKERS:-16}"
RESULTS="${RESULTS:-$WORK_DIR/bench-results.tsv}"

php() { "$PHP_BIN" -d memory_limit=1G -d max_execution_time=0 "$@"; }
console() { (cd "$MAUTIC_ROOT" && php bin/console "$@"); }

# 1. Mailer DSN for this run (bulk mode, no/low throttling); local.php needs % escaped as %%.
DSN="mautic+ses+api://fake:fake@default?region=eu-central-1&ratelimit=${RATELIMIT}&bulk=${MODE}&bulk_batch_size=50&bulk_concurrency=${BULK_CONC}&endpoint=http%%3A%%2F%%2F127.0.0.1%%3A${FAKE_PORT}"
"$PHP_BIN" -r '$f=$argv[1]; require $f; $parameters["mailer_dsn"]=$argv[2]; file_put_contents($f, "<?php\n\$parameters = ".var_export($parameters, true).";\n");' "$MAUTIC_ROOT/config/local.php" "$DSN"
console cache:clear >/dev/null 2>&1
rm -f "$MAUTIC_ROOT/var/tmp/ses_send_quota.json" "$MAUTIC_ROOT/var/cache/prod/ses_token_bucket.json"

# 2. Fresh fake SES server (clean log, optional latency, several workers); run.sh fake-down finds it through the pid file.
pkill -f "\-S 127.0.0.1:${FAKE_PORT} " 2>/dev/null || true
: > "$FAKE_LOG"
rm -f "$FAKE_LOG.state.json"
cat > "$WORK_DIR/fake-ses-delay.php" <<'PHP'
<?php
$delay = (int) (getenv('FAKE_SES_DELAY_MS') ?: 0);
if ($delay > 0) { usleep($delay * 1000); }
require getenv('FAKE_SES_FRONT');
PHP
FAKE_SES_LOG="$FAKE_LOG" FAKE_SES_RATE="$RATELIMIT" FAKE_SES_DELAY_MS="$FAKE_SES_DELAY_MS" FAKE_SES_FRONT="$PLUGIN_ROOT/Tests/E2E/fake-ses-server.php" PHP_CLI_SERVER_WORKERS="$FAKE_WORKERS" \
  nohup "$PHP_BIN" -S "127.0.0.1:$FAKE_PORT" "$WORK_DIR/fake-ses-delay.php" >"$WORK_DIR/fake-ses-bench.out" 2>&1 &
echo $! > "$WORK_DIR/fake-ses-$FAKE_PORT.pid"
curl -s --retry 10 --retry-connrefused --retry-delay 1 -o /dev/null "http://127.0.0.1:$FAKE_PORT/v2/email/account"

# 3. Seed and send under /usr/bin/time (-l on macOS/BSD, -v with GNU time on Linux).
SEED_HTML_FILE="$HTML" SEED_NAME="bench-$MODE" SEED_SUBJECT="Benchmark $MODE" STATE_FILE="$STATE" php "$HERE/seed.php" "$MAUTIC_ROOT" "$COUNT" example.test 2>&1 | grep -E '^(created|segment|email)'
EMAIL_ID="$("$PHP_BIN" -r 'echo json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR)["email_id"];' "$STATE")"
TIMING="$WORK_DIR/bench-time-$MODE.txt"
if /usr/bin/time -l true >/dev/null 2>&1; then TIME_FLAG=-l; else TIME_FLAG=-v; fi
( cd "$MAUTIC_ROOT" && /usr/bin/time "$TIME_FLAG" "$PHP_BIN" -d memory_limit=1G -d max_execution_time=0 bin/console mautic:broadcasts:send --channel=email --id="$EMAIL_ID" --limit=1000000 --batch="$BATCH" --bypass-locking 2>"$TIMING" | grep -E '^\| Email' )

# 4. Collect metrics from the fake SES log (this email only) and the timing output.
"$PHP_BIN" -d memory_limit=1G -- "$FAKE_LOG" "$TIMING" "$EMAIL_ID" "$MODE" "$COUNT" "$RATELIMIT" "$FAKE_SES_DELAY_MS" "$BATCH" "$RESULTS" <<'PHP'
<?php
[, $log, $timing, $emailId, $mode, $count, $rate, $delay, $batch, $results] = $argv;
$bulk = $raw = $bulkBytes = $rawBytes = $templateBytes = $dataBytes = $entries = 0;
$handle = fopen($log, 'r');
while (false !== ($line = fgets($handle))) {
    $request = json_decode($line, true);
    if (!is_array($request)) {
        continue;
    }
    $body = $request['request'] ?? [];
    if (str_ends_with($request['path'], '/outbound-bulk-emails')) {
        $tags = array_column($body['BulkEmailEntries'][0]['ReplacementTags'] ?? [], 'Value', 'Name');
        if (($tags['X-EMAIL-ID'] ?? '') !== $emailId) {
            continue;
        }
        ++$bulk;
        $bulkBytes += strlen(json_encode($body));
        $entries += count($body['BulkEmailEntries']);
        $templateBytes += strlen(json_encode($body['DefaultContent'] ?? []));
        foreach ($body['BulkEmailEntries'] as $entry) {
            $dataBytes += strlen((string) ($entry['ReplacementEmailContent']['ReplacementTemplate']['ReplacementTemplateData'] ?? ''));
        }
    } elseif (str_ends_with($request['path'], '/outbound-emails')) {
        $tags = array_column($body['EmailTags'] ?? [], 'Value', 'Name');
        if (($tags['X-EMAIL-ID'] ?? '') !== $emailId) {
            continue;
        }
        ++$raw;
        $rawBytes += strlen(json_encode($body));
    }
}
fclose($handle);
$time = (string) file_get_contents($timing);
$grab = static fn (string $pattern): ?string => preg_match($pattern, $time, $m) ? $m[1] : null;
if (null !== $grab('/(\d+)\s+maximum resident set size/')) {
    // BSD time -l: seconds and bytes.
    [$real, $user, $sys] = [$grab('/([\d.]+) real/'), $grab('/([\d.]+) user/'), $grab('/([\d.]+) sys/')];
    $rssMb = (int) $grab('/(\d+)\s+maximum resident set size/') / 1024 / 1024;
} else {
    // GNU time -v: kilobytes and an elapsed time of [h:]m:ss.cc.
    $elapsed = array_reverse(explode(':', (string) $grab('/Elapsed \(wall clock\) time[^:]*: ([\d:.]+)/')));
    $real = sprintf('%.2f', (float) $elapsed[0] + 60 * (int) ($elapsed[1] ?? 0) + 3600 * (int) ($elapsed[2] ?? 0));
    [$user, $sys] = [$grab('/User time \(seconds\): ([\d.]+)/'), $grab('/System time \(seconds\): ([\d.]+)/')];
    $rssMb = (int) $grab('/Maximum resident set size \(kbytes\): (\d+)/') / 1024;
}
$recipients = 'auto' === $mode ? $entries : $raw;
$totalBytes = $bulkBytes + $rawBytes;
$header = "mode\tcontacts\tratelimit\tdelay_ms\tbatch\trequests\trecipients_submitted\tbytes\tbytes_per_recipient\treal_s\tuser_s\tsys_s\tmax_rss_mb";
$row = implode("\t", [$mode, $count, $rate, $delay, $batch, $bulk + $raw, $recipients, $totalBytes, sprintf('%.0f', $totalBytes / max(1, $recipients)), $real ?? '?', $user ?? '?', $sys ?? '?', sprintf('%.0f', $rssMb)]);
if (!is_file($results)) {
    file_put_contents($results, $header."\n");
}
file_put_contents($results, $row."\n", FILE_APPEND);
echo $header, "\n", $row, "\n";
if ('auto' === $mode) {
    printf("template bytes total %d, replacement data total %d (%.0f/recipient)\n", $templateBytes, $dataBytes, $dataBytes / max(1, $entries));
}
echo "appended to $results\n";
PHP
