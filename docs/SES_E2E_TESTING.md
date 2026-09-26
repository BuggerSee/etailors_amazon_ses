# Testing SES bulk sending end to end

Three tiers, run in this order. Each one covers what the previous one cannot:

| Tier                                                      | Sends to                                    | Proves                                                                                                                                                    | Does not prove                                                                     |
|-----------------------------------------------------------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| [1. Offline](#tier-1-offline-against-the-fake-ses-server) | The fake SES server on your machine         | Mautic integration: token resolution, shared template and replacement data, outbox states, retries, statistics reconciliation and raw fallback decisions. | SES rendering, SES acceptance, SES limits, IAM, SNS events.                        |
| [2. SES sandbox](#tier-2-ses-sandbox)                     | SES and its mailbox simulator               | SES accepts the requests, renders the template as expected and publishes events that reach Mautic through SNS.                                            | Production volume, quota and throughput, deliverability to real mailbox providers. |
| [3. Production canary](#tier-3-production-canary)         | About 50 internal addresses, production SES | The production configuration end to end: DSN, IAM, configuration set, SNS callback, Messenger workers and the `retry` cron.                               | Behaviour at full-list volume.                                                     |

All commands run from the Mautic project root. Table names carry your Mautic table prefix (`db_table_prefix`), if
you use one. The plugin's [README](../README.MD#bulk-sending-with-shared-ses-templates-experimental) describes the
DSN options, the `mautic:ses:bulk` command and the outbox states used below.

## Tier 1: offline against the fake SES server

`Tests/E2E/offline/run.sh` scripts this tier: fake server, seeding, sending (inline or through parallel Messenger
workers), the `mautic:ses:bulk` commands and a verifier that checks every step. Its
[README](../Tests/E2E/offline/README.md) also covers the prerequisites, the Mautic 6 and 7 install notes (router
script for PHP's built-in server, admin password strength, `continue_sending`, `unsubscribe_text` with `|URL|`),
retry timing with `retry --now`, the async mode and `bench.sh`. The manual equivalent:

1. Start the fake server from the plugin directory and leave it running:

   ```bash
   FAKE_SES_RATE=80 FAKE_SES_LOG=/tmp/fake-ses-requests.jsonl php -S 127.0.0.1:4566 Tests/E2E/fake-ses-server.php
   ```

   `FAKE_SES_RATE` is the `MaxSendRate` its account endpoint reports (default 80). `FAKE_SES_LOG` is the request log,
   one JSON line per request with the request and the response (default `fake-ses-requests.jsonl` in PHP's temporary
   directory). The server remembers which `flaky@` addresses it has seen in `<FAKE_SES_LOG>.state.json`; delete that
   file before a new run with the same addresses.

2. Set this mailer DSN:

   ```text
   mautic+ses+api://fake:fake@default?region=eu-central-1&ratelimit=80&bulk=auto&endpoint=http%3A%2F%2F127.0.0.1%3A4566
   ```

   In **Settings > Configuration > Email Settings** that is scheme `mautic+ses+api`, host `default`, user and
   password `fake`, and the options `region` = `eu-central-1`, `ratelimit` = `80`, `bulk` = `auto` and
   `endpoint` = `http://127.0.0.1:4566`; enter the plain URL there, the form URL-encodes option values itself.
   Mautic stores `%` as `%%` when the DSN is saved through the UI, so `config/local.php` then contains
   `endpoint=http%%3A%%2F%%2F127.0.0.1%%3A4566`. When you write `mailer_dsn` in `config/local.php` by hand, double
   every `%` yourself. Clear the cache after every DSN change:

   ```bash
   bin/console cache:clear
   ```

3. Register the plugin and create the outbox tables:

   ```bash
   bin/console mautic:plugins:reload
   bin/console mautic:ses:bulk install
   ```

   `install` prints `[OK] SES bulk tables are ready.`

4. Create four contacts (in the UI or by CSV import) with these local parts, all on one domain, for example
   `success@ses-e2e.test`. The fake server decides by the exact local part, whatever the domain:

   | Local part  | Fake SES result for the recipient                              | Outbox state after the send |
   |-------------|----------------------------------------------------------------|-----------------------------|
   | `success`   | `SUCCESS` with a message ID (any local part not listed here)   | `accepted`                  |
   | `transient` | `TRANSIENT_FAILURE`, on every attempt                          | `retry`                     |
   | `flaky`     | `TRANSIENT_FAILURE` in the first request, `SUCCESS` afterwards | `retry`                     |
   | `rejected`  | `MESSAGE_REJECTED`                                             | `rejected`                  |

   `throttled` (`ACCOUNT_THROTTLED`) and `http500` (HTTP 500 for the whole request, which leaves every recipient of
   that request `unknown` with reason `ambiguous_request_failure`) are available too; keep `http500` out of this run,
   because it changes the outcome of every recipient in its request.

5. Create a segment with the filter **Email** contains `@ses-e2e.test`, and fill it:

   ```bash
   bin/console mautic:segments:update
   ```

6. Create a segment email for that segment (**Channels > Emails > New > Segment Email**) and publish it. On
   Mautic 7, set **Continue sending emails to contacts added to the segment after sending has started?** to **Yes**,
   as the harness does with `continue_sending`.

7. Send it:

   ```bash
   bin/console mautic:broadcasts:send --channel=email --id=<email id>
   ```

   With the default `messenger_dsn_email` of `sync://`, this command sends. With a queued transport (for example
   `doctrine://default`) it only queues the messages; then send them with:

   ```bash
   bin/console messenger:consume email
   ```

   and stop the worker (Ctrl-C) once the queue is empty. Mautic's summary counts all four recipients as sent; the
   outbox holds the outcome per recipient.

8. Check the outbox:

   ```bash
   bin/console mautic:ses:bulk status --email-id=<email id>
   ```

   Expected (row order may differ): one recipient `accepted`, two in `retry`, one `rejected`, one request.

   ```text
    ------ ------------------ ----------- ------------------- ------------ ----------
     Mode   Submission state   SES event   Reason              Recipients   Attempts
    ------ ------------------ ----------- ------------------- ------------ ----------
     bulk   accepted                                           1            1
     bulk   rejected                       MESSAGE_REJECTED    1            1
     bulk   retry                          TRANSIENT_FAILURE   2            2
    ------ ------------------ ----------- ------------------- ------------ ----------
   ```

   The `SES event` column stays empty in this tier, because no SNS events arrive. Add `--json` for the same data as
   JSON.

9. Reconcile the statistics:

   ```bash
   bin/console mautic:ses:bulk sync-stats
   ```

   Expected: `Reconciled 1 failed recipient statistics. No contacts were added to DNC.` Only `rejected@` is now
   marked failed, and no contact got a Do Not Contact entry:

   ```bash
   bin/console dbal:run-sql "SELECT email_address, is_failed FROM email_stats WHERE email_id = <email id>"
   bin/console dbal:run-sql "SELECT COUNT(*) FROM lead_donotcontact d JOIN leads l ON l.id = d.lead_id WHERE l.email LIKE '%@ses-e2e.test'"
   ```

10. Retry. A row in `retry` becomes due 60 s after its failed attempt, so wait at least 60 s after the send, then:

    ```bash
    bin/console mautic:ses:bulk retry
    ```

    It prints `Processed up to 2 due recipients. Inspect status for their outcomes.` and reconciles statistics as
    `sync-stats` does. `retry` handles the due rows of every email sent in the same SES region, so rows
    left over from earlier test emails raise that count. `status` now shows `flaky@` accepted and `transient@` still
    in `retry` after its second attempt:

    ```text
     bulk   accepted                                           2            3
     bulk   rejected                       MESSAGE_REJECTED    1            1
     bulk   retry                          TRANSIENT_FAILURE   1            2
    ```

    `transient@` becomes due again 120 s after this attempt and 240 s after the next. When the fourth attempt fails
    too, `status` shows it `rejected` with reason `retry_exhausted:TRANSIENT_FAILURE` and 4 attempts, and that
    `retry` run marks its statistic failed. To skip the waits, make the rows due before each `retry`, as
    `run.sh retry --now` does:

    ```bash
    bin/console dbal:run-sql "UPDATE ses_bulk_deliveries SET next_attempt = 0 WHERE email_id = <email id> AND state = 'retry'"
    ```

11. Inspect the request log, here with `jq`. The shared template of each request:

    ```bash
    jq -c 'select(.path == "/v2/email/outbound-bulk-emails") | .request.DefaultContent.Template.TemplateContent' /tmp/fake-ses-requests.jsonl
    ```

    The subject and HTML contain `{{v_…}}` placeholders and the plain text `{{t_…}}` placeholders (or only
    `{{ses_plain_text}}` when the text part cannot be shared). The per-recipient entries:

    ```bash
    jq -c 'select(.path == "/v2/email/outbound-bulk-emails") | .request.BulkEmailEntries[] | {to: .Destination.ToAddresses, data: .ReplacementEmailContent.ReplacementTemplate.ReplacementTemplateData, headers: .ReplacementHeaders, tags: .ReplacementTags}' /tmp/fake-ses-requests.jsonl
    ```

    Each entry's replacement data holds that recipient's values (email address, tracked links, unsubscribe and web
    view links), its headers hold the recipient's `List-Unsubscribe` when Mautic adds one, and its tags hold
    `X-EMAIL-ID` and `mautic_delivery_id`. `.response.BulkEmailEntryResults` shows the status the fake server
    returned per entry.

12. Check the raw fallback. Create a second segment email for the same segment with an attachment
    (**Advanced > Attachments**), send it as in step 7, and count the requests per endpoint:

    ```bash
    jq -r '.path' /tmp/fake-ses-requests.jsonl | sort | uniq -c
    ```

    The attachment email adds one `/v2/email/outbound-emails` (`SendEmail` with raw MIME) request per recipient and
    no `/v2/email/outbound-bulk-emails` request, and `mautic:ses:bulk status --email-id=<second email id>` shows no
    rows, because a message-level fallback takes the unchanged raw path, which does not use the outbox. The fake
    server accepts every raw request, whatever the local part. The transport also logs
    `SES raw sending: message is not eligible for shared templates.` with the reason `attachments`, but at `info`
    level: Mautic's production configuration writes only errors to `var/logs/prod-<date>.php`, so the line appears in
    `var/logs` only in an environment that logs `info` messages, such as Mautic's `dev` environment (which needs
    Mautic's development dependencies).

What this tier proves: Mautic resolves the tokens and the plugin turns them into one shared template plus
per-recipient data; every recipient is recorded before submission and classified from its own result; retries,
backoff, exhaustion and statistics reconciliation work; ineligible emails fall back to raw before anything is
submitted. Run with Messenger workers (`run.sh all-async`), it also shows that parallel workers never claim the same
delivery.

What it does not prove: that SES renders the template the way a simple `{{var}}` substitution suggests, that SES
accepts the requests (size limits, quotas, throttling, credentials, IAM), or anything about SNS events: the `SES event`
column stays empty and the callback is not exercised.

## Tier 2: SES sandbox

The sandbox limits you to verified recipients and the mailbox simulator, which is enough here. Mails to the mailbox
simulator are billed like any other, but they do not count against your sending quota and do not affect your
reputation (bounce and complaint rates). Steps 1 to 4 prepare AWS and Mautic; the offline harness's live mode scripts
steps 5 to 8 (see below step 4), and those steps are its manual equivalent.

1. In the SES console of the region you test, verify a sender identity (a domain or an address). The IAM user needs
   the permissions from the README's [AWS SES Configuration](../README.MD#3-aws-ses-configuration) plus
   `ses:SendBulkEmail`.
2. Create an SNS topic, and an SES configuration set with an SNS event destination that publishes to that topic the
   event types `Send`, `Delivery`, `Bounce`, `Complaint`, `Reject` and `Rendering Failure` (`SEND`, `DELIVERY`,
   `BOUNCE`, `COMPLAINT`, `REJECT` and `RENDERING_FAILURE` in the API). Make it the default configuration set of the
   sender identity, or add the custom header `X-SES-CONFIGURATION-SET` with its name to the test email
   (**Advanced > Custom headers**). The harness needs the default configuration set, because the email it seeds
   carries no custom headers.
3. Set the mailer DSN with your credentials, `bulk=auto`, the topic ARN and no `endpoint`, then clear the cache:

   ```text
   mautic+ses+api://<AWS_ACCESS_KEY>:<AWS_SECRET_KEY>@default?region=<AWS_REGION>&bulk=auto&sns_topic_arn=<SNS_TOPIC_ARN>
   ```

   In a DSN written by hand, URL-encode the access key and the secret: a secret access key can contain `/` and `+`,
   which become `%2F` and `%2B`. The Email Settings form encodes its user and password fields itself. In
   `config/local.php`, double every `%` as in Tier 1, step 2. `sns_topic_arn` is the exact ARN of the topic from
   step 2: the callback refuses notifications from any other topic.

   Each request carries at most as many recipients as the effective send rate (`ratelimit`, or the account's
   `MaxSendRate`). A sandbox account may send 1 message per second, so each request then carries one recipient.
   Setting `ratelimit` above the account's rate (for example `ratelimit=6`) puts several recipients into one request,
   but SES may throttle them: the affected rows go to `retry`, and after four throttled attempts to `rejected` with
   `retry_exhausted:<status>`.
4. Expose the local Mautic over HTTPS with a tunnel, for example:

   ```bash
   cloudflared tunnel --url http://localhost:8080
   ```

   or `ngrok http 8080`, with the port of your local Mautic. Subscribe the SNS topic with the HTTPS protocol to the
   callback URL from the README's [SNS Callback Configuration](../README.MD#sns-callback-configuration):

   ```text
   https://<tunnel host>/mailer/callback
   ```

   The plugin confirms the subscription itself, but only after `sns_topic_arn` is configured, because it checks the
   topic of every callback first. The subscription then shows as confirmed in the SNS console.

The offline harness scripts steps 5 to 8 with `LIVE=1` (details in its
[README](../Tests/E2E/offline/README.md#live-mode-ses-sandbox)). `LIVE=1` refuses the actions that need the fake
server, never changes `mailer_dsn`, and makes `verify` check the outbox and Mautic's tables instead of a fake request
log. From the plugin checkout, with `SEED_FROM` set to an address of the verified sender identity:

```bash
export MAUTIC_ROOT=/path/to/mautic PHP_BIN=php STATE=/tmp/ses-live-state.json SEED_FROM=sender@your-verified.example
LIVE=1 Tests/E2E/offline/run.sh seed-live you@verified.example
LIVE=1 Tests/E2E/offline/run.sh send
LIVE=1 Tests/E2E/offline/run.sh status
LIVE=1 Tests/E2E/offline/run.sh verify --live
# wait for SNS: repeat status until the SES event column is filled for every recipient
LIVE=1 Tests/E2E/offline/run.sh verify --live --after-events
LIVE=1 Tests/E2E/offline/run.sh sync
```

`seed-live` creates contacts for the five simulator addresses of step 5 and the addresses given (or reuses the ones
from an earlier run and removes their email Do Not Contact entries, so that Mautic sends to them again), a new segment
and a segment email with the harness's newsletter fixture, which carries tracked links and `{unsubscribe_url}`.
`verify --live` prints each recipient's outbox operation, state, SES event, reason, message ID and Do Not Contact
entries, exits non-zero when a check fails, and checks:

| Check                                                                   | What it proves                                                                  |
|-------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| One outbox row and one `email_stats` row per seeded recipient           | Every recipient was persisted before submission, and Mautic counts it as sent.  |
| Every recipient submitted through `bulk` (`raw` with `--live-raw`)      | No recipient fell back to raw sending.                                          |
| Every recipient `accepted` with an SES message ID                       | SES accepted every recipient with these credentials, IAM policy, sender identity and inline template. |
| `--after-events`: the `SES event` and Do Not Contact entry from the table in step 5 for each simulator address | SES rendered and delivered, bounced or reported the complaint, and each event came back through the configuration set, SNS and the callback to the right outbox row and contact. |
| `--after-events`: `sent` or `delivered` for every other address         | The real mailbox got at least the `Send` event and no bounce, rejection or rendering failure. |

`sync` then marks `bounce@` and `suppressionlist@` failed, as in step 8. Step 9 stays manual.

5. Create contacts for the mailbox simulator, and one verified address whose mailbox you can read:

   | Recipient                                 | SES behaviour                                        | Expected `SES event` | Mautic                                                             |
   |-------------------------------------------|------------------------------------------------------|----------------------|--------------------------------------------------------------------|
   | `success@simulator.amazonses.com`         | Delivered                                            | `delivered`          | No Do Not Contact entry                                            |
   | `bounce@simulator.amazonses.com`          | Hard bounce                                          | `bounced`            | Do Not Contact, bounced (reason 2); `is_failed` after `sync-stats` |
   | `complaint@simulator.amazonses.com`       | Delivered, then a complaint                          | `complained`         | Do Not Contact, unsubscribed (reason 1)                            |
   | `ooto@simulator.amazonses.com`            | Delivered, with an out-of-office reply to the sender | `delivered`          | No Do Not Contact entry                                            |
   | `suppressionlist@simulator.amazonses.com` | Hard bounce, as if the address were suppressed       | `bounced`            | Do Not Contact, bounced (reason 2); `is_failed` after `sync-stats` |
   | Your verified address                     | Delivered                                            | `delivered`          | No Do Not Contact entry                                            |

6. Put them in a segment, create a segment email with a subject token, tracked links and `{unsubscribe_url}` (or
   `{unsubscribe_text}` with `|URL|` in the `unsubscribe_text` setting), and send it as in Tier 1, step 7.
7. Directly after the send, `bin/console mautic:ses:bulk status --email-id=<email id>` shows every recipient
   `accepted` with mode `bulk` (or `retry`, where SES throttled). Once the events arrive, the `SES event` column
   shows the values from the table. The event with the highest rank is kept (`complained` over `bounced`,
   `rendering_failed` and `rejected`, those over `delivered`, and `delivered` over `sent`), so `complaint@` ends as
   `complained` although its `Delivery` event arrives too. A `rendering_failed` event means SES could not render the
   template for that recipient.
8. Run `bin/console mautic:ses:bulk sync-stats` and check the statistics and the Do Not Contact entries:

   ```bash
   bin/console dbal:run-sql "SELECT email_address, is_failed FROM email_stats WHERE email_id = <email id>"
   bin/console dbal:run-sql "SELECT l.email, d.channel, d.reason, d.comments FROM lead_donotcontact d JOIN leads l ON l.id = d.lead_id WHERE l.email LIKE '%@simulator.amazonses.com'"
   ```

9. Compare the message in your own mailbox with the same email sent raw: switch the DSN to `bulk=off`, clear the
   cache, send a clone of the email to the same segment, and compare subject, HTML, plain text, tracked links,
   unsubscribe link and the `List-Unsubscribe` header. Apart from the per-send tracking hashes they must match.

What this tier proves: the installed SDK and IAM policy can call `SendBulkEmail` with inline templates and
replacement headers, SES accepts and renders the requests as Mautic would have rendered them, and SES events reach
the outbox and Mautic's Do Not Contact list through the configuration set, SNS and the callback.

What it does not prove: behaviour at production volume, under the production quota and send rate, with the
production Messenger workers, or deliverability to real mailbox providers.

## Tier 3: production canary

1. Deploy the plugin with `aws/aws-sdk-php` 3.325.1 or newer and create the outbox tables
   (`bin/console mautic:ses:bulk install`, or the plugin migration once the plugin version increases).
2. Check that the production configuration set publishes all six event types to the topic in `sns_topic_arn` and is
   applied to the emails, and that the IAM user has `ses:SendBulkEmail`.
3. Add the `retry` cron and confirm that it exists for the user that runs Mautic's cron jobs:

   ```text
   */5 * * * * php /path/to/mautic/bin/console mautic:ses:bulk retry
   ```

   ```bash
   crontab -l | grep 'mautic:ses:bulk retry'
   ```

4. Add `bulk=auto` to the production DSN, clear the cache and restart the `messenger:consume` workers so that they
   use the new DSN.
5. Send a newsletter to an internal segment of about 50 addresses.
6. Compare `bin/console mautic:ses:bulk status --email-id=<email id>` with the email's statistics in Mautic: the
   outbox recipients should add up to Mautic's sent count, all of them `accepted` with mode `bulk`, and the
   `SES event` column should fill with `delivered` (or `bounced` and `complained` where that is expected). Look into
   every `unknown`, `retry`, `rejected` or `raw` row and its reason before going on. When `status` shows no rows for
   the email, the whole email took the raw path.
7. Only then send to the full list. To go back, set `bulk=off`, clear the cache and restart the workers; `retry` then
   refuses to run, and rows left in `retry` wait until `bulk=auto` is configured again.

What this tier proves: the production DSN, IAM policy, configuration set, SNS subscription, Messenger workers and
`retry` cron work together for a small send, and Mautic's statistics agree with the outbox.

What it does not prove: throughput and resource use at full-list volume. Compare those with the raw path's figures
from earlier sends of the same list.
