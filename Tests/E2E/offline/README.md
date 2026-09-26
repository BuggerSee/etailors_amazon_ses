# Offline end-to-end harness

These scripts drive a real local Mautic with this plugin against the fake SES server in `Tests/E2E/`. They do not
need AWS: seed contacts and a segment email, send the broadcast, run the outbox retry and statistics sync, and check
every step against the fake server's request log, the outbox tables and Mautic's statistics.

| File        | Purpose                                                                                                     |
|-------------|-------------------------------------------------------------------------------------------------------------|
| `run.sh`    | Runner: fake server, seeding, sending (inline or through Messenger workers), `mautic:ses:bulk` commands, verification. |
| `seed.php`  | Creates contacts, a segment and a published segment email through Mautic's own models (no HTTP, no API).    |
| `verify.php`| Cross-checks the fake SES log, `ses_bulk_deliveries`/`ses_bulk_contents` and `email_stats`; exits non-zero on any failed check. |
| `bench.sh`  | Times `bulk=auto` against `bulk=off` for the same seed and appends the numbers to `bench-results.tsv`.      |

## Prerequisites

- PHP 8.2 or newer on the command line, with `pdo_mysql`, plus `curl`. `bench.sh` also needs `/usr/bin/time`
  (BSD `time -l` on macOS, GNU `time -v` on Linux).
- A MySQL or MariaDB server.
- A Mautic 5, 6 or 7 install in the Composer "recommended project" layout (`bin/console`, `config/local.php`,
  `docroot/`), with this plugin in `docroot/plugins/AmazonSesBundle` (a symlink to this checkout works; the project
  then needs the plugin's Composer dependencies, for example
  `composer require aws/aws-php-sns-message-validator:^1.10 aws/aws-sdk-php:^3.325.1`).
- The outbox tables. `run.sh prepare` creates them with `bin/console mautic:ses:bulk install`.
- Synchronous email sending (`'messenger_dsn_email' => 'sync://'` in `config/local.php`). With a queued transport,
  `send` only queues the messages; run `bin/console messenger:consume email` before `status` and `verify`, or use
  `run.sh async`, which switches to a Doctrine queue and back by itself (see
  [Queued sending with parallel workers](#queued-sending-with-parallel-workers)).
- The mailer DSN below.

### Mailer DSN

Point the plugin at the fake server with the `endpoint` DSN option (URL-encoded):

```
mautic+ses+api://fake:fake@default?region=eu-central-1&ratelimit=80&bulk=auto&bulk_batch_size=50&endpoint=http%3A%2F%2F127.0.0.1%3A4566
```

When written to `config/local.php` directly, every `%` must be doubled, because Mautic's configuration treats `%` as a
parameter delimiter:

```php
'mailer_dsn' => 'mautic+ses+api://fake:fake@default?region=eu-central-1&ratelimit=80&bulk=auto&bulk_batch_size=50&endpoint=http%%3A%%2F%%2F127.0.0.1%%3A4566',
```

The port in `endpoint` must equal `FAKE_PORT`. Clear the cache after every DSN change (`run.sh prepare` does).

### Local install notes

- Mautic 6 refuses logins, in the UI and for API basic auth alike, when the stored password scores below 3 on its
  zxcvbn strength estimator. Give `bin/console mautic:install <site_url> ... --admin_password=...` a strong value, for
  example a four-word passphrase with digits and a symbol; `Admin12345!` scores 2 and is refused. The harness itself
  never logs in; this only matters when you open the UI or call the API.
- PHP's built-in web server serves CSS, JavaScript and images only when its router script returns `false` for files
  that exist. Save this as `docroot/router.php`:

  ```php
  <?php
  // Router for PHP's built-in server: serve existing files directly, everything else through Mautic.
  $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/';
  if ('/' !== $path && is_file(__DIR__.$path)) {
      return false;
  }
  $_SERVER['SCRIPT_NAME'] = '/index.php';
  $_SERVER['SCRIPT_FILENAME'] = __DIR__.'/index.php';
  $_SERVER['PHP_SELF'] = '/index.php';
  require __DIR__.'/index.php';
  ```

  and start it from the project root with `php -d memory_limit=1G -S 127.0.0.1:8080 -t docroot docroot/router.php`.
- Mautic 7 only adds the `List-Unsubscribe` header when the body contains `{unsubscribe_text}` and the
  `unsubscribe_text` configuration contains `|URL|` (the default is empty), or when the body contains
  `{unsubscribe_url}` directly. The verifier requires a recipient-specific `List-Unsubscribe` header on every entry.
  The default seed newsletter carries `{unsubscribe_url}`; for your own newsletters set, in `config/local.php`:

  ```php
  'unsubscribe_text' => '<a href="|URL|">Unsubscribe</a> to no longer receive emails from us.',
  ```

## Configuration

`run.sh` and `bench.sh` read everything from environment variables:

| Variable        | Default                                                   | Meaning                                                                         |
|-----------------|-----------------------------------------------------------|---------------------------------------------------------------------------------|
| `PHP_BIN`       | `php`                                                     | PHP binary for Mautic's console and the fake server (console runs get `-d memory_limit=1G`). |
| `MAUTIC_ROOT`   | required                                                  | Mautic project root (not needed for `fake-up`/`fake-down`).                     |
| `PLUGIN_ROOT`   | the checkout containing these scripts                     | Checkout that provides `Tests/E2E/fake-ses-server.php`.                         |
| `FAKE_PORT`     | `4566`                                                    | Port of the fake server; must match `endpoint` in the DSN.                      |
| `FAKE_LOG`      | `<PHP sys_get_temp_dir()>/fake-ses-requests.jsonl`        | JSONL request log. The fake server's pid file and output are written next to it. |
| `FAKE_SES_RATE` | `80`                                                      | `MaxSendRate` reported by the fake account endpoint.                            |
| `STATE`         | `ses-e2e-state.json` next to `FAKE_LOG`                   | Seed state (`stamp`, `segment_id`, `email_id`, `contact_ids`, `emails`).        |
| `BATCH`         | `100` (`500` in `bench.sh`)                               | Contacts per `mautic:broadcasts:send` batch; `verify` uses it to count the expected requests. |
| `WORKERS`       | `2`                                                       | `messenger:consume email` processes that `async` runs in parallel.              |

`seed.php` also reads `SEED_HTML_FILE` (send your own HTML instead of the built-in fixture; its plain text is derived
by stripping tags), `SEED_NAME` and `SEED_SUBJECT`.

When you test more than one Mautic install, give each its own `FAKE_PORT`, `FAKE_LOG` and `STATE`, for example:

```
export MAUTIC_ROOT=$HOME/mautic7 FAKE_PORT=4567 FAKE_LOG=/tmp/ses-e2e7/fake-ses-requests.jsonl STATE=/tmp/ses-e2e7/state.json
```

## Running

```
export MAUTIC_ROOT=/path/to/mautic PHP_BIN=php
Tests/E2E/offline/run.sh all 100
```

`all [count] [domain]` runs every step below in order and stops at the first failure:

| Step                                     | What it does                                                                                     |
|------------------------------------------|--------------------------------------------------------------------------------------------------|
| `prepare`                                | `cache:clear`, `mautic:plugins:reload`, `mautic:ses:bulk install`.                               |
| `fake-up`                                | Starts `php -S 127.0.0.1:$FAKE_PORT Tests/E2E/fake-ses-server.php` with an empty log and flaky state. Refuses to start when the port is taken. |
| `seed [count] [domain]`                  | `count` (default 100) contacts `successNNN.<stamp>@<domain>` plus `transient@`, `throttled@`, `rejected@` and `flaky@<stamp>.<domain>` (default domain `example.test`), a segment with all of them, and a published segment email with `publishUp` in the past (and `continue_sending` on Mautic 7). |
| `send`                                   | `mautic:broadcasts:send --channel=email --id=<email> --limit=100000 --batch=$BATCH --bypass-locking`. Mautic's default `--limit` of 100 would stop the broadcast early. |
| `status`                                 | `mautic:ses:bulk status --email-id=<email>`.                                                     |
| `verify`                                 | Checks the state right after the send.                                                           |
| `retry --now`                            | Makes this email's `retry` rows due and runs `mautic:ses:bulk retry --limit=1000`.               |
| `status`, `verify --after-retry`         | Checks the state after one retry run.                                                            |
| `sync`, `verify --after-retry --after-sync` | `mautic:ses:bulk sync-stats`, then checks the failed statistics too.                          |

`fake-down` stops the fake server (also the one `bench.sh` starts). Each step can be run on its own, for example
`run.sh seed 20`, `run.sh send`, `run.sh verify`.

`all-async [count] [domain]` runs the same steps, with `async` in place of `send`, `status` and `verify`:

```
WORKERS=2 Tests/E2E/offline/run.sh all-async 120
```

The fake server fails bulk entries by the exact local part of the recipient: `transient@` returns
`TRANSIENT_FAILURE`, `throttled@` returns `ACCOUNT_THROTTLED`, `rejected@` returns `MESSAGE_REJECTED`, and `http500@`
fails the whole request with HTTP 500. `flaky@` returns `TRANSIENT_FAILURE` for the first request that contains that
address and `SUCCESS` afterwards; the addresses already seen are kept in `<FAKE_LOG>.state.json`. The run stamp goes
into the domain so these local parts stay exact and every run gets fresh addresses.

### Queued sending with parallel workers

In production, `mautic:broadcasts:send` only queues the email on Symfony Messenger, and several
`bin/console messenger:consume email` workers call the transport. Each worker deserialises the queued `MauticMessage`
(recipient metadata with `hashId`, `emailId` and `tokens` included) before `doSend()` runs, and all workers on a host
share the token-bucket file in Mautic's cache directory. `run.sh async` reproduces this on one machine:

1. Sets `messenger_dsn_email` to `doctrine://default` in `<MAUTIC_ROOT>/config/local.php` (re-exported with
   `var_export` like `bench.sh` does, so comments in it are lost) and clears the cache. `default` is the Doctrine
   connection; Symfony creates the `messenger_messages` table (without Mautic's table prefix) on the first send.
2. Runs `send`, which now only queues: one Messenger message per `mautic:broadcasts:send` batch (`BATCH`), each
   carrying its recipients. The 124 recipients of `all-async 120` become two messages with the default `BATCH=100`.
3. Counts the queued messages and starts `WORKERS` processes of
   `bin/console messenger:consume email --time-limit=120 --limit=<n> -vv` at once, with `<n>` = queued messages divided
   by `WORKERS`, rounded up, so each worker exits after its share instead of idling until the time limit. Their output
   goes to `messenger-worker-<i>.log` next to `FAKE_LOG`.
4. Waits for the workers, fails when one of them failed or messages are left in the queue, then runs `status` and
   `verify`.
5. Restores `messenger_dsn_email` to `sync://` and clears the cache in an exit trap, so this also happens when a step
   fails or the run is interrupted (the trap stops workers that are still running).

A worker takes at most `<n>` messages. When the queue does not divide evenly (three messages for two workers), one
worker keeps polling until the 120 s time limit. A message whose handler throws is queued again by Mautic's Messenger
retry strategy and can stay behind; `async` then reports the messages left, and `bin/console messenger:consume email`
drains them.

Mautic 5, 6 and 7 agree on the parts `async` relies on: the parameter is `messenger_dsn_email`, the transport is named
`email` (Mautic routes `SendEmailMessage` to it), and `--time-limit` and `--limit` are checked after each message and
after each empty poll (`--sleep`, default 1 s), so an idle worker stops about a second after its time limit. In all
three, `-vv` prints only the worker banner, because Mautic's production Monolog configuration has no console handler;
the claim owners that `verify` prints show how the recipients were split instead. What differs:

|                                        | Mautic 5 (5.2)   | Mautic 6 (6.0.9)                                                       | Mautic 7 (7.2.1)    |
|----------------------------------------|------------------|------------------------------------------------------------------------|---------------------|
| Symfony Messenger                      | 5.4              | 6.4                                                                    | 7.4                 |
| Acknowledged message on MySQL/MariaDB  | as Mautic 6      | Row kept with `delivered_at = '9999-12-31 23:59:59'`, deleted by a later fetch | Row deleted at once |

`async` counts the queue without the `9999-12-31` rows, so its check works on all three. Mautic 6 and 7 were run
locally; the Mautic 5 column comes from the 5.2 sources (`app/config/config.php`, `composer.lock`, Symfony 5.4's
Doctrine transport) and has not been run.

### Retry timing and the `--now` shortcut

A retryable failure (`TRANSIENT_FAILURE`, `ACCOUNT_THROTTLED`) leaves the row in `retry`. The first retry becomes due
60 s after the failed attempt, the next 120 s after the second failure, then 240 s after the third. A fourth failure
marks the row `rejected` with reason `retry_exhausted:<status>`.

`run.sh retry` without flags only processes rows that are already due, so directly after `send` it does nothing
until 60 s have passed. `run.sh retry --now` skips the wait: it runs
`UPDATE <prefix>ses_bulk_deliveries SET next_attempt = 0 WHERE email_id = <email> AND state = 'retry'` through
`bin/console dbal:run-sql` (the unit tests set `next_attempt` the same way) and then runs the retry command. Running
`retry --now` three times after the send uses up all four attempts of `transient@` and `throttled@`.
`verify --after-retry` requires `retry` for them while fewer than four submissions are logged and `rejected` with
reason `retry_exhausted:<status>` (the status the fake server returned) once four are.

`mautic:ses:bulk retry` processes the due rows of every email sent with the same region and access key, not only the
seeded one, and it reconciles failed statistics as `sync-stats` does.

## What `verify` checks

`verify.php <mautic-root> <state.json> <fake-ses-log.jsonl> [--after-retry] [--after-sync]` reads the database
credentials from `<mautic-root>/config/local.php`, keeps only the logged requests whose `X-EMAIL-ID` tag is the seeded
email, prints `PASS`/`FAIL` per check and exits 1 when any check fails (2 on bad arguments).

| Check                                                                      | What it proves                                                                  |
|----------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| one outbox row per seeded recipient                                        | Every recipient was persisted before submission.                                |
| every recipient went through the shared-template path                      | No recipient fell back to raw sending (`operation = bulk`).                     |
| no outbox row was claimed more than once before the retry runs (no flag only) | No row has `attempts > 1` right after the send. Each claim adds an attempt and a failed row is due again 60 s later at the earliest, so after `async` this proves that two workers never claimed the same delivery. |
| bulk request N carries an inline template                                  | `SendBulkEmail` uses `DefaultContent.Template.TemplateContent` with subject and HTML. |
| bulk request N has <=L entries and one result per entry                    | Batches respect the per-request limit L: 50, `bulk_batch_size` or `ratelimit` / `bulk_concurrency` from `mailer_dsn`, whichever is smallest (40 with the DSN above). |
| entry N renders and reconciles                                             | Per submission: the verifier substitutes `{{var}}` from the entry's replacement data and finds the recipient's address and tracking hash in the HTML, no unreplaced Mautic token (`{contactfield=…}`, `{unsubscribe_text}`, `{webview_text}`, `{tracking_pixel}`, `{trackable=…}`, `{leadfield=…}`), no leftover `{{`/missing variable, a `List-Unsubscribe` header with the recipient's hash, the `mautic_delivery_id` and `X-EMAIL-ID` tags, the fake status expected for that local part and attempt, the SES `MessageId` stored on accepted rows, and resubmission only after `TRANSIENT_FAILURE`/`ACCOUNT_THROTTLED`. At a recipient's latest submission it also checks the outbox state (and, for an exhausted retry, the reason `retry_exhausted:<status>`) and that the outbox attempt count equals the number of logged submissions. |
| every seeded recipient appears exactly once across the initial bulk entries | The set of submitted addresses equals the seeded set; with the resubmission rule above, nothing was sent twice unless the outbox retried it. |
| all bulk requests share one identical inline template                      | The content is shared by every batch and retries reuse the stored template.     |
| initial request count equals ceil(recipients / L) per batch of `BATCH`     | Batches are full: each `mautic:broadcasts:send` batch of `BATCH` contacts is one message, split into requests of up to L recipients. |
| Mautic recorded one email_stats row per recipient / every outbox row maps to an email_stats row | Mautic's statistics and the outbox agree by tracking hash.     |
| sync-stats flagged exactly the rejected recipients as failed (`--after-sync`) | `email_stats.is_failed` count equals the number of `rejected` outbox rows.    |
| no do-not-contact entries were created by transport failures               | Transport failures never mark the seeded contacts do-not-contact.               |

`verify` also prints `claims: <n> owner(s), rows per owner: …`, the number of outbox rows per value of the `claim`
column. `BulkSender` claims with one owner token per `send()` call, i.e. per Messenger message, and keeps it on the row,
so after `async` it shows how the recipients were split between the handled messages (100 and 24 for `all-async 120`);
after a retry run the retried rows carry the retry run's owner. Rows without an owner are left out, and the line says
`skipped` when no row has one.

Expected outbox states per stage:

| Recipient                | no flag    | `--after-retry`                                                    |
|--------------------------|------------|--------------------------------------------------------------------|
| `successNNN.<stamp>@…`   | `accepted` | `accepted`                                                         |
| `rejected@`              | `rejected` | `rejected`                                                         |
| `flaky@`                 | `retry`    | `accepted`                                                         |
| `transient@`, `throttled@` | `retry`  | `retry` after 2 or 3 submissions; `rejected` with reason `retry_exhausted:TRANSIENT_FAILURE` / `retry_exhausted:ACCOUNT_THROTTLED` after the 4th |

## What the harness cannot prove

- SES-side rendering. The fake server does not render templates; the verifier's own `{{var}}` substitution mirrors
  simple replacement only. Use the SES sandbox with the mailbox simulator to confirm what recipients receive.
- Real events. No `Send`, `Delivery`, `Bounce`, `Complaint`, `Reject` or `Rendering Failure` notifications arrive,
  so the `event` column stays empty and the SNS callback path is not exercised.
- SES limits and behaviour: request size limits, quotas, real throttling, account-level suppression, credentials,
  IAM policies and regions.
- Raw sending beyond counting: raw requests are only counted, their MIME content is not checked.
- Queued sending beyond one host and one transport: `async` covers the Doctrine transport with workers on one
  machine. Other transports (AMQP, Redis), workers on several hosts (each host has its own token-bucket file) and
  Messenger's failure transport are not exercised, nor is a worker that dies during a request (its rows turn `unknown`).

## Benchmark

```
Tests/E2E/offline/bench.sh <auto|off> <count> [html-file]
```

`bench.sh` rewrites `mailer_dsn` in `<MAUTIC_ROOT>/config/local.php` (the file is re-exported with `var_export`,
comments in it are lost), clears the cache and the plugin's send-quota and token-bucket files, restarts the fake server
with an empty log and `FAKE_WORKERS` workers, seeds `count` contacts (plus the four injection addresses), runs
`mautic:broadcasts:send` under `/usr/bin/time` and appends one line to `bench-results.tsv`: requests, recipients
submitted, request bytes (the JSON-encoded request bodies in the log), wall-clock, user and system seconds, and the
sending process's maximum RSS. The DSN stays in place and the fake server keeps running afterwards
(`run.sh fake-down` stops it). After `bench.sh off …` the install sends raw until `mailer_dsn` says `bulk=auto` again
(`bench.sh auto …` also sets it), and `run.sh verify` fails on raw sends.

| Knob                | Default                              | Meaning                                                              |
|---------------------|--------------------------------------|----------------------------------------------------------------------|
| `RATELIMIT`         | `100000`                             | DSN `ratelimit` (100000 means no throttling, so local resources are measured); also the fake account's `MaxSendRate`. |
| `BULK_CONC`         | `2`                                  | DSN `bulk_concurrency` for `auto` runs.                              |
| `BATCH`             | `500`                                | Contacts per `mautic:broadcasts:send` batch.                         |
| `FAKE_SES_DELAY_MS` | `0`                                  | Artificial latency per fake SES request.                             |
| `FAKE_WORKERS`      | `16`                                 | `PHP_CLI_SERVER_WORKERS` for the fake server.                        |
| `RESULTS`           | `bench-results.tsv` next to `FAKE_LOG` | Results file.                                                      |

The newsletter used for the numbers below (a compiled 164 KB MJML newsletter) is not committed; pass your own HTML as
`html-file` (it becomes `SEED_HTML_FILE`). Without it the small built-in fixture is sent.

Example, measured on 2026-09-26 against Mautic 7.2.1 on an Apple Silicon Mac, one sending process, with the
164 KB newsletter, after the plain-text part became shared between recipients. The first pair ran with the defaults
(`RATELIMIT=100000`, no latency), the second with `RATELIMIT=80 FAKE_SES_DELAY_MS=100`:

```
mode  contacts  ratelimit  delay_ms  batch  requests  recipients_submitted  bytes      bytes_per_recipient  real_s  user_s  sys_s  max_rss_mb
auto  1000      100000     0         500    21        1004                  15095024   15035                7.78    5.38    0.26   136
off   1000      100000     0         500    1004      1004                  320853092  319575               10.76   8.46    0.40   631
auto  400       80         100       500    9         404                   6239442    15444                7.07    2.54    0.15   122
off   400       80         100       500    404       404                   129108076  319574               14.95   4.36    0.23   216
```

With throttling and latency one sender reached about 57 recipients/s with `bulk=auto` and about 27 recipients/s with
`bulk=off`. A bulk recipient cost about 15 KB of request body, and the request counts equal ceil(recipients / 50), so
every batch but the remainder carried 50 entries. Before the plain-text part was shared, each bulk recipient carried
its own copy of it (66 KB per recipient in total for this newsletter), and the 1 MB request limit kept the batches at
about 16 entries.
