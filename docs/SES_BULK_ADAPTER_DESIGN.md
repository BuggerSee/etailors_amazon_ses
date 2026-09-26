# SES bulk adapter: implementation notes

Status: implemented as an opt-in adapter (`bulk=auto`; `bulk=off` stays the default). The
[README](../README.MD#bulk-sending-with-shared-ses-templates-experimental) describes how to enable and operate it. This
file lists where each part lives, the limits that decide eligibility and what is still to validate.

## Implemented, by file

- `Mailer/Bulk/SharedTemplateCompiler.php`: one inline template and per-recipient replacement data from Mautic's resolved tokens, with the reason when a message or recipient is not eligible.
- `Mailer/Bulk/BulkBatcher.php`: batches of identical request fields, at most 50 entries and 1,000,000 bytes.
- `Mailer/Bulk/BulkSender.php`: atomic claims, a bounded window of in-flight requests without SDK retries, per-recipient result classification and error-level logging of recipients left rejected or unknown.
- `Mailer/Bulk/DeliveryStore.php`, `Entity/BulkDelivery.php`, `Entity/BulkContent.php`: the outbox, retry backoff, claim expiry, SES event recording, reconciliation into `email_stats.is_failed` and pruning.
- `Mailer/Transport/AmazonSesTransport.php`: the message-level eligibility gate, per-recipient raw fallback, the per-request recipient limit and the shared token bucket for every submission, retries included.
- `Mailer/Factory/AmazonSesTransportFactory.php`: the `bulk`, `bulk_batch_size`, `bulk_concurrency` and `endpoint` DSN options.
- `Command/BulkCommand.php`: `mautic:ses:bulk install|status|retry|sync-stats|prune`.
- `Migrations/Version_1_0_42.php`: the outbox tables for existing installations.
- `EventSubscriber/CallbackSubscriber.php`: SES events passed to the outbox.
- `Tests/E2E/`: a fake SES server and an offline harness, run against local Mautic 6.0.9 and 7.2.1 with synchronous sending and with Messenger workers.

## Invariants

- A delivery is identified by `sha256(scope | email ID | tracking hash | recipient)`, where the scope is the SES region
  and access key. A re-delivered Messenger message maps to the same rows and cannot reset their outcome.
- Every recipient of a message is recorded in one transaction before the first request. A failure up to the commit
  reaches Mautic and leaves nothing behind; a failure after it is logged and left to the outbox, because Mautic would
  otherwise resend the message under new tracking hashes.
- SDK retries are disabled. An outcome that may follow acceptance (timeout, broken connection, HTTP 5xx, malformed
  result, expired claim) is `unknown` and never resubmitted automatically; only SES events resolve it.
- Every submission is charged per recipient against the shared token bucket. A request carries at most
  send rate / `bulk_concurrency` recipients, because the requests of one window can reach SES together.
- Claims that never reached SES (a local failure) and, for 30 hours, recipients over the 24-hour quota are handed back
  without using up one of the four attempts.

## Eligibility limits

The decision is made before anything is submitted. The first recipient decides for the whole message; a later
recipient that fails is sent raw on its own, through the outbox.

- Message: attachments, CC or BCC, an explicit MIME body, a non-UTF-8 part, no body, literal `{{` or `}}`, token keys
  that are not `{…}` or differ only in case, array token values, headers other than `X-*`, `List-*`, `Precedence`,
  `Feedback-ID`, `Auto-Submitted` and the address, subject, date, message ID and MIME headers, a `Sender` that differs
  from `From`, a `Return-Path` that differs from `X-SES-FEEDBACK-FORWARDING-EMAIL-ADDRESS`, more than 15 headers.
  `Return-Path` itself is sent as `FeedbackForwardingEmailAddress`.
- Recipient: replacement data over 262,144 bytes, a request with the recipient alone over 1,000,000 bytes, a header
  name over 126 bytes or a value over 870 bytes or with a line break, header characters outside printable ASCII,
  invalid UTF-8, literal `{{` or `}}` in a token value. Header values that resolve to an empty string are left out.
- Request: at most 50 entries, 1,000,000 bytes (headroom below the documented inline limit) and
  send rate / `bulk_concurrency` recipients.

## Open validation items

- Validation against SES itself on Mautic 6 and 7 with Messenger: rendering of the shared template, event delivery and
  statistics (the sandbox and canary tiers in [SES_E2E_TESTING.md](SES_E2E_TESTING.md)).
- Throughput and throttling at 80 recipients/s against SES, including how SES treats the requests of one window
  arriving together.
- Broader eligibility (dynamic-content blocks, shared attachments), each only with fixtures showing output equivalent
  to the raw path.
- Recipient outcomes reach Mautic only through `sync-stats`. A provider-neutral batch outcome contract in Mautic core
  would be the cleaner integration; it is a separate proposal.
