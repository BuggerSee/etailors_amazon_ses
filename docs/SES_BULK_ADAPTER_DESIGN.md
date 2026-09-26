# SES bulk adapter: implementation and contribution boundaries

Status (2026-09-26): implemented on this branch as an opt-in adapter (`bulk=auto`; `bulk=off` stays the default), on top of upstream plugin 1.0.41 (`46b8ddb`) and the Mautic 6/7 snapshots in [the research](SES_BULK_TEMPLATE_RESEARCH.md). Implemented, by file:

- `Mailer/Bulk/SharedTemplateCompiler.php`: one inline template and per-recipient replacement data from Mautic's resolved tokens, with the reason when a message or recipient is not eligible.
- `Mailer/Bulk/BulkBatcher.php`: batches of identical request fields, at most 50 entries and 1,000,000 bytes.
- `Mailer/Bulk/BulkSender.php`: atomic claims, a bounded window of in-flight requests without SDK retries, and per-recipient result classification.
- `Mailer/Bulk/DeliveryStore.php`, `Entity/BulkDelivery.php`, `Entity/BulkContent.php`: the outbox, retry backoff, claim expiry, SES event recording and reconciliation into `email_stats.is_failed`.
- `Mailer/Transport/AmazonSesTransport.php`: the message-level eligibility gate, per-recipient raw fallback and the shared token bucket for every submission, retries included.
- `Mailer/Factory/AmazonSesTransportFactory.php`: the `bulk`, `bulk_batch_size`, `bulk_concurrency` and `endpoint` DSN options.
- `Command/BulkCommand.php`: `mautic:ses:bulk install|status|retry|sync-stats`.
- `Migrations/Version_1_0_42.php`: the outbox tables for existing installations.
- `EventSubscriber/CallbackSubscriber.php`: SES events passed to the outbox.
- `Tests/E2E/`: a fake SES server and an offline harness, run against local Mautic 6.0.9 and 7.2.1 with synchronous sending and with Messenger workers.

Remaining: validation against SES itself on Mautic 6/7 with Messenger (the sandbox and canary tiers in [SES_E2E_TESTING.md](SES_E2E_TESTING.md)), benchmarks at 80 recipients/s against SES, and broader eligibility (section 4 below). The rest of this document is the design as written before the implementation; the [README](../README.MD#bulk-sending-with-shared-ses-templates-experimental) describes the adapter as built.

## Decision

Implement SES payload construction and submission in `pm-pmaas/etailors_amazon_ses`. Mautic already provides `TokenTransportInterface` and recipient metadata. No Mautic core patch is required to prototype bulk submission or render recipient content.

Correct partial-failure accounting across synchronous sending and asynchronous Messenger delivery is a separate integration requirement. The current core interface does not return recipient outcomes. Do not promise that a production implementation with accurate core statistics and durable recovery will need no core changes until integration tests establish the available hooks. Do not treat the existing plugin's log-only failure handling as acceptable proof of compatibility.

Any core contribution should be provider-neutral: recipient outcomes and retry ownership for batch transports, without AWS template or SDK dependencies.

## Actual newsletter inspection (2026-09-26)

Inspected the complete user-provided `newsletter-endlich-hat-apple-den-wecker-repariert.mjml` locally. The attachment remains unchanged and is not copied into the plugin or its distributable tests.

- Source size: 41,663 bytes, 696 lines. This is MJML source size, not compiled HTML or SES request size.
- Three explicit Mautic tokens, each appearing once: `{contactfield=email}` at line 684, `{webview_text}` at line 687 and `{unsubscribe_text}` at line 690.
- No contact-name tokens, conditional recipient blocks or dynamic-content tokens were found in the source. The news, offers, product content and layout are shared.
- 35 literal href attributes with 25 distinct decoded values. These are source links, not a count of final tracking tokens: compilation and Mautic link processing may change the representation.
- 11 explicit image source attributes, all HTTPS. No embedded image data or CID references in the source; Mautic's image-embedding configuration and separately attached assets remain unknown.
- The affiliate tags and UTM parameters in these source URLs are fixed campaign values, not recipient personalization.

Decision: prioritize a shared-template prototype for this newsletter, rather than requiring a full-body wrapper implementation first. Use synthetic fixtures with the same structure for committed tests.

Operate on the HTML/plain text and recipient metadata at Mautic's transport boundary, after MJML compilation and Mautic preparation. SES does not receive the MJML source. Preserve the email-address footer and locally resolved webview/unsubscribe fragments. Preserve any recipient-specific click URLs, open pixel and headers that Mautic adds. These additional values cannot be enumerated from the MJML alone; generated subject, text alternative and headers are absent from this attachment.

Verify equivalent rendered output for multiple synthetic recipients using Mautic 6/7 before enabling the path. The source is a strong candidate for shared templating, not proof of compatibility with the live installation. Actual compiled body size, recipient data size, request count and CPU savings remain unmeasured.

## Plugin contribution sequence

### 1. Rendering compatibility and payload prototype

Start implementation from upstream 1.0.41, retaining recent SNS authentication and attribution fixes; this workspace's checked-out source is older. Keep new behavior disabled by default.

Extract the existing per-recipient rendering into a reusable reference/fallback component without changing raw output. Preserve token sorting, Mautic replacement semantics, tracking hashes, sender/reply-to handling, unsubscribe headers and email attribution. Use that output as the compatibility reference; the optimized path should not require constructing every finished body just to build a shared template.

For the first bulk prototype, identify eligible common HTML/plain text and map the remaining recipient tokens to generated SES variables. Mautic remains responsible for resolving tracking, contact values and HTML fragments. Preserve replacement ordering and context-specific escaping; confirm actual SES insertion and literal delimiter behavior. Render headers locally and compare subject, HTML and text to the raw reference. Unsupported replacement semantics must fall back before submission.

A full-body wrapper is an optional diagnostic or separately benchmarked compatibility mode, not a prerequisite or the primary optimization for this newsletter. It still uploads and renders complete recipient bodies.

Initially require one recipient per destination, ordinary unsigned email and supported headers. Route attachments, embedded images, CC/BCC, unsupported MIME and oversized replacement data through the existing raw path before submission. Broaden eligibility only with fixtures and integration evidence.

Build bounded batches grouped by all request-level SES fields: sender and identity ARN, reply-to, configuration set, feedback forwarding settings, and template structure. Enforce both destination count and serialized request size. Preserve resolved recipient headers and tags; never silently discard fields to make a message eligible.

Tests: capture equivalent raw and structured content for Unicode, HTML/plain text, dynamic blocks, subject tokens, tracking/unsubscribe URLs, sender variations and extension headers. Test size boundaries, incompatible groups, fallback and unchanged original messages. Validate payloads against an AWS SDK model supporting inline templates and replacement headers; establish a tested SDK dependency floor.

### 2. Submission, rate limiting and durable outcomes

Reuse the shared limiter, charging by recipients for initial sends and retries. Batch size must fit both provider limits and limiter capacity, including accounts below 50 recipients/sec. Preserve cross-worker limiting; a bulk API request does not count as one email.

Associate each submitted entry with its logical delivery identity, and retain each returned status and provider message ID. Classify explicit transient failures separately from permanent rejection and unknown acceptance. Retry only explicitly failed, retryable recipients. Missing or malformed response entries are unknown outcomes, not confirmed failures.

Persist delivery state before acknowledging the parent queue job. Design for concurrent claims and worker restarts. Define the logical identity using the campaign/send occurrence plus recipient, not recipient address alone, so future legitimate newsletters are not suppressed. Validate how this identity survives Mautic serialization before selecting its fields.

The SES request has no client idempotency token in the inspected API. A connection loss or crash after acceptance can leave an unknown outcome; a local ledger cannot guarantee exactly-once delivery. Do not automatically resend unknown entries or switch them to raw. Define reconciliation using SES events where available and expose unresolved outcomes for an explicit recovery policy.

Verify SDK and Messenger retry behavior, including automatic HTTP retries, so hidden whole-request retries do not undermine per-recipient handling. Add rendering-failure event support alongside ordinary delivery/bounce events.

Tests: mixed results, throttling, permanent rejection, exhausted retries, response loss, worker termination and queue redelivery. Assert accepted recipients are not intentionally retried, unresolved recipients are retained, and retry work shares the recipient budget.

### 3. Mautic integration and opt-in release

Run the same scenarios on Mautic 6 and 7, with direct sending and Messenger. Trace when Mautic records a send versus when SES accepts or rejects it. Verify recipient statistics, failure visibility and campaign behavior; SES acceptance is not final delivery.

If existing public hooks can support accurate accounting, keep the complete implementation in the plugin. If they cannot, implement the generic core integration described below rather than patching vendor files or suppressing failures. Production enablement depends on this decision being resolved.

Compare against the existing raw path at the user's fixed 80 recipients/sec: API calls, bytes uploaded, CPU, peak memory, number of workers and actual accepted throughput. Measure real batch occupancy and full serialized request size, including template and recipient data. Document raw fallback reasons. Enable only after seed-delivery rendering checks and failure tests pass.

### 4. Broaden template eligibility

After the shared informational newsletter path is proven, consider more complex personalized newsletters, dynamic-content blocks and shared attachments. Preserve Mautic's resolved dynamic content and context-specific replacement rules; retain raw fallback when translation is not equivalent. Do not expand eligibility based only on template appearance.

## Possible Mautic core contribution

Propose a provider-neutral batch outcome contract and integration tests. Before choosing an interface, trace both direct and Messenger execution: a synchronous return value alone cannot update the original caller after a queued job executes.

The design must represent accepted, retryable failure, permanent rejection and unknown outcome per logical recipient delivery; specify who owns retry scheduling; and connect eventual outcomes to Mautic statistics. Preserve existing single-message transports and distinguish provider acceptance from delivery. Do not assume a custom exception alone fixes asynchronous redelivery.

This can benefit multiple provider plugins, but is a separate core proposal, not a prerequisite for the offline SES prototype. Whether it is required for the production plugin is an integration-test result still to establish.

## Submission targets

- Plugin PR(s): `pm-pmaas/etailors_amazon_ses`, based on current upstream, for rendering extraction, SES adapter, configuration, limiter integration, outcome persistence and provider tests.
- Conditional core PR: `mautic/mautic`, for generic batch outcome/accounting support if existing hooks are insufficient. Keep SES-specific behavior out of core.

No application code or live email sending was changed while writing this design.
