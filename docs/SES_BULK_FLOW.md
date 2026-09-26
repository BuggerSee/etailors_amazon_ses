# How `bulk=auto` sends a newsletter

Two diagrams: the path of one Mautic email from the queue to SES and back, and the life of one recipient row in the outbox. GitHub renders them inline.

## End-to-end flow

```mermaid
flowchart TB
  subgraph M["Mautic 6 / 7 (unchanged)"]
    A["Segment broadcast, campaign action,<br/>send-to-contact, example send"] --> B["MailHelper tokenized queue<br/>one message per email, N recipients<br/>metadata per recipient: emailId, hashId, resolved tokens"]
  end
  B --> C{"AmazonSesTransport::doSend()"}
  C -- "bulk=off (default)" --> R["Raw path, unchanged from 1.0.41<br/>one SendEmail per recipient<br/>CommandPool micro-batches + inline retries"]
  C -- "bulk=auto" --> G{"Gate"}
  G -- "no recipient metadata (system mail),<br/>or message ineligible: attachments, CC/BCC,<br/>custom MIME, non-UTF-8, unsupported header" --> R
  G -- "rows already in the outbox<br/>(queue replay)" --> O
  G -- "eligible" --> T["SharedTemplateCompiler<br/>Shared inline templates<br/>plain-text fallback may split batches<br/>per-recipient v_ / t_ data, or ses_plain_text"]
  T --> E["bulkEntry() per recipient<br/>Destination, ReplacementHeaders (List-Unsubscribe...),<br/>ReplacementTags: X-EMAIL-ID + mautic_delivery_id"]
  E -- "recipient ineligible<br/>(oversized data, bad header value)" --> RF["raw fallback row<br/>full MIME, one SendEmail later"]
  E --> O[("Outbox<br/>ses_bulk_contents (template + request fields)<br/>ses_bulk_deliveries (one row per recipient)<br/>saved in ONE transaction before any request")]
  RF --> O
  O --> BB["BulkBatcher<br/>effective concurrency c = min(rate, bulk_concurrency)<br/>≤ min(50, bulk_batch_size, floor(rate ÷ c)) recipients<br/>≤ 1 MB per request, identical request fields"]
  BB --> BS["BulkSender<br/>atomic claim per row (one owner)<br/>token bucket: 1 token per recipient, file shared by all workers<br/>SendBulkEmail, up to c requests in flight, SDK retries off"]
  BS --> SES[("Amazon SES v2")]
  SES -- "entry SUCCESS" --> ACC["accepted + SES message id<br/>payload dropped (≈1 KB row)"]
  SES -- "TRANSIENT_FAILURE<br/>ACCOUNT_THROTTLED" --> RET["retry<br/>due after 60 s, 120 s, 240 s<br/>4th failure ⇒ rejected"]
  SES -- "MESSAGE_REJECTED<br/>validation error" --> REJ["rejected"]
  SES -- "timeout, 5xx,<br/>malformed response" --> UNK["unknown<br/>never resent automatically"]
  SES -. "Send / Delivery / Bounce /<br/>Complaint / Reject / Rendering Failure<br/>via SNS" .-> CB["CallbackSubscriber<br/>SNS signature + topic ARN check"]
  CB --> DNC["Bounce / Complaint ⇒ Do Not Contact<br/>(existing behaviour)"]
  CB --> EV["DeliveryStore::recordEvent()<br/>row found by the mautic_delivery_id tag<br/>sent → delivered / bounced / complained /<br/>rendering_failed / rejected, atomic precedence"]
  EV --> O
  subgraph K["bin/console mautic:ses:bulk (cron)"]
    K1["retry: claim due retry rows across messages,<br/>same bucket, same batching"]
    K2["sync-stats: rejected state or<br/>bounced / rejected / rendering_failed event<br/>⇒ email_stats.is_failed (no Do Not Contact)"]
    K3["prune --older-than=30: terminal rows<br/>skip failures awaiting reconciliation"]
    K4["status --email-id / --json"]
  end
  O --> K1 --> BS
  O --> K2
  O --> K3
  O --> K4
  W["Messenger workers × N<br/>share the bucket file and the outbox claims:<br/>one owner per active claim, shared recipient rate limit<br/>due retryable rows may be submitted again"] -.-> BS
```

## Life of one recipient row

```mermaid
stateDiagram-v2
  [*] --> pending: enqueue, one transaction per message
  pending --> sending: claim (atomic UPDATE, one owner token)
  retry --> sending: claim once next_attempt is due
  sending --> accepted: SUCCESS + message id
  sending --> retry: TRANSIENT_FAILURE / ACCOUNT_THROTTLED / FAILED, attempts < 4
  sending --> retry: local pre-flight failure (released, no attempt spent)
  sending --> rejected: MESSAGE_REJECTED, validation error, 4th failure
  sending --> unknown: timeout, 5xx, malformed response, claim older than 10 min
  accepted --> accepted: SNS events overlay: sent, delivered, bounced, complained, rejected, rendering_failed
  unknown --> accepted: SNS Send / Delivery event proves acceptance
  rejected --> [*]: sync-stats reconciles failure, then prune after retention
  accepted --> [*]: prune after retention once any failure event is reconciled
  unknown --> [*]: prune after retention
```

Rules the diagrams encode: `bulk=off` never touches the outbox; every SES submission charges the shared token bucket per recipient; a raw fallback is decided before anything is submitted; accepted, unknown and currently sending rows are skipped on replay while retained; a queue replay is answered from the outbox, not from the current email definition. Claims prevent concurrent submission of the same row; due pending/retry rows can be submitted, and pruning ends replay protection for deleted rows.
