# SES scaling and performance implementation plan

Status: proposed implementation plan; no sending behavior has been changed.

Baseline: upstream `pm-pmaas/etailors_amazon_ses`, version **1.0.41**, commit `46b8ddb`, fetched on 2026-09-25. The local fork remains at `628a27b`, 40 commits behind that upstream revision. Implementation must start from the reviewed upstream code, retaining its SNS signature/topic validation, DSN decoding, email-ID tags, regional clients, and token-bucket fixes. This document does not merge either branch.

Scope: all twelve items in the corrected scaling review, a concrete performance program, and additional newsletter operations features. The user reports a **150,000-recipient newsletter list**, an approximately **80 recipients/second SES rate**, and satisfactory throughput with multiple workers. Verify the precise account rate/daily quota during implementation; do not treat a higher sending rate as the primary objective. The principal benchmark is now a 150,000-recipient campaign at 80/s. Larger/multi-host profiles are future capability checks, not required infrastructure for this deployment. Mautic/PHP versions, queue backend, worker count and message sizes remain to be recorded.

## Recommended focus for this newsletter

At 80 recipients/sec, submitting 150,000 recipients takes a theoretical minimum of **31 minutes 15 seconds**. If current sends are already close to that, additional worker concurrency cannot materially improve completion time without a larger SES quota. No quota increase or deployment expansion is assumed.

Build a better newsletter transport around the working sending path:

| Priority | User-visible contribution | Why it matters at this scale | Work packages |
| --- | --- | --- | --- |
| 1 | Campaign delivery report with recipient-level explanations | Distinguish accepted, delivered, delayed, suppressed and failed; locate problems by recipient domain/provider and see a remaining-work estimate. | F1, B2, D2, E1 |
| 2 | Pause, resume and failed-only recovery | An interrupted 150k send should resume from durable progress, and a small failed subset should be repairable without repeating the campaign. | B1, B2, F4 |
| 3 | Suppression reconciliation and send-time eligibility | Recover from missed feedback and skip addresses SES will suppress, even if the contact entered the queue earlier. | F2, D2 |
| 4 | Same throughput with less CPU, RAM and callback overhead | Measure resources per 150k campaign; stream MIME, cache immutable context/certificates and reduce request barriers where useful. | C1–C3, D2 |
| 5 | SES preflight and personalized-message inspection | Catch quota, configuration-set, sender and payload problems before a large dispatch. | A2, E1, F3 |
| 6 | Optional bulk-template feasibility study | Check whether compatible groups and payload sizes can reduce 150,000 calls toward a best-case 3,000; retain the 80-recipient/sec budget. | E3 |
| 7 | Delivery-aware provider pacing | Optionally slow new submissions to a provider showing sustained delivery trouble while other destinations continue. | F5 |

The bulk-call example is arithmetic at the documented maximum of 50 destinations per SendBulkEmail call, assuming one recipient per entry, compatible templates and no retries. It is **up to 50× fewer calls, not 50× faster sending**. Actual grouping can be smaller because of rate, content and payload-size constraints. [AWS template limits](https://docs.aws.amazon.com/ses/latest/dg/send-personalized-email-api.html)

Follow-up research found the historical Mautic custom-header blocker and the AWS change that removed it. Inspection of Mautic 6.x and 7.x confirms that tokenized batching hooks exist, but the current plugin still has no active SES bulk adapter. Raw MIME cannot simply be passed to SendBulkEmail; rendering parity and recipient-level failures across the mailer/queue boundary remain unresolved integration work. Shared-template translation and batching locally rendered bodies have different benefits and limitations; the latter can hit the documented 1 MB inline request limit far below 50 entries. Treat E3 as a feasibility decision before committing to implementation. See [bulk-template research](SES_BULK_TEMPLATE_RESEARCH.md).

Keep Redis/multi-host coordination available in the complete plan, but defer it unless the user introduces independent hosts or measurements expose a real coordination problem. Keep priority queues optional unless transactional mail competes with this newsletter. Reuse Mautic's existing campaign, segment, scheduling and unsubscribe features; add SES-specific transport insight rather than another campaign editor.

## 1. Outcomes and constraints

1. Saturate the configured sending budget with fewer worker resources when sufficient ready work exists.
2. Keep rendered-payload memory bounded independently of the total campaign size.
3. Preserve recipient-specific content, tracking, unsubscribe behavior, and Mautic statistics.
4. Recover known failures without replaying known successes. Record ambiguous outcomes explicitly.
5. Coordinate all participating senders using the same AWS account/region budget across hosts.
6. Keep delivery feedback current enough to stop sending to suppressed recipients.

SES imposes recipient-based rate and rolling 24-hour limits. More concurrency can remove local bottlenecks; it cannot raise those quotas. A useful planning approximation is:

`accepted throughput <= min(configured/SES rate, available concurrency / mean request latency, rendering capacity, persistence capacity)`

For raw single-recipient sends, 80/s at 200 ms mean request latency needs roughly 16 requests in flight across the deployment before headroom. This is a sizing estimate, not a benchmark. Daily quota, rendering, retries, and feedback can extend the 31 min 15 sec newsletter submission minimum. Delivery to recipient servers can continue after submission finishes. [AWS quota semantics](https://docs.aws.amazon.com/ses/latest/dg/manage-sending-quotas.html)

## 2. Performance opportunities, evidence, and measurement

References below are relative to the upstream revision, not the older workspace files. Evidence means visible code behavior; expected benefits still require measurement.

| ID | Change | Evidence / hypothesis | Measure and completion criterion |
| --- | --- | --- | --- |
| PERF-1 | Render and send a bounded stream | Transport lines 166–178 build all commands before chunking. | Measure incremental rendered-payload memory separately from Mautic's input metadata. A tenfold increase in input recipients must not cause a corresponding tenfold increase in rendered-buffer memory; enforce count and byte caps. |
| PERF-2 | Replace batch barriers with a rolling request window | Lines 181–200 wait for every request in one micro-batch before starting the next. | Inject slow requests and show ready work continues as slots free up; report p50/p95/p99 latency and accepted recipients/sec. |
| PERF-3 | Remove redundant outer throttling when coverage is complete | Constructor line 124 sets `setMaxPerSecond(1)` in addition to the shared bucket. Symfony's parent transport sleeps between send calls. | Benchmark single-recipient jobs and large tokenized jobs separately. Small jobs should no longer be capped at approximately one send call/sec per worker; all paths must still acquire quota. |
| PERF-4 | Move delayed retries off sending workers | Lines 205–230 sleep for 1/2/4 seconds and finish retries before advancing. | Under transient failures, ready recipients continue progressing; retry queue remains bounded and uses the same rate budget. Depends on durable recovery. |
| PERF-5 | Prepare invariant email configuration once | `setReplyTo()` repeats metadata lookup, entity access, splitting, and Address creation per payload. | Profile allocations, CPU time, and SQL count; cache immutable settings for the logical send. Do not claim N+1 SQL without measurement: Doctrine may already serve identity-map hits. |
| PERF-6 | Optimize token/MIME work only where profiling supports it | Per recipient: clone message, sort tokens, replace content, serialize complete MIME. | Record CPU and allocation profiles. Preserve replacement ordering, escaping, dynamic headers, tracking and attachments; require golden-message equivalence before accepting an optimization. |
| PERF-7 | Reduce callback certificate fetches | `SnsWebhookAuthenticator` creates a default validator, whose inspected implementation fetches SigningCertURL during validation. | Cache validated certificate material with bounded TTL/size and single-flight refresh; count fetches and callback latency. Verify every message signature, including on cache hits. |
| PERF-8 | Reduce feedback database contention | HTTP callback does contact lookup and DNC writes synchronously. | Queue verified events; measure database queries, lock time, flush count and suppression lag. Deduplicate writes and process in bounded units while retaining Mautic model side effects. |
| PERF-9 | Reduce limiter/control-plane overhead | File bucket repeatedly opens/locks/reads/writes; quota fetching can happen simultaneously after expiry. | Measure lock/Redis wait and operations per accepted recipient. Use shared atomic decisions and one quota refresher; optimize token reservation only after measuring its fairness costs. |
| PERF-10 | Experiment with template-based bulk sends | Current active path renders raw MIME and makes one API call per destination payload. | Prototype only compatible templates; compare CPU, bytes transferred and API calls per recipient, with exact personalization/tracking parity and per-entry failure handling. Remain opt-in. |

The current eight-message micro-batch at 80/s, with every API request taking 200 ms, has a simplified per-worker ceiling near 40/s before other work. A rolling window of about 16 concurrent requests could hide that latency for one worker at 80/s. This is an illustrative model, not a measured speedup. The user's multiple-worker deployment is already working well; test whether the same throughput can be maintained with fewer worker resources rather than promising faster completion.

Reuse the correctly scoped SES client and its HTTP handler across requests; do not recreate clients per recipient. Measure connection reuse, DNS/TLS time, upload bytes, compression/encoding cost, and network distance to the SES region before adding connection tuning. Do not relocate sending regions automatically: identities, quotas and feedback configuration must match.

## 3. Proposed structure

Keep AmazonSesTransport as the Mautic/Symfony adapter. Extract only components required by the changes:

- `SendContext` / `PayloadFactory`: immutable campaign settings and lazy recipient payload conversion.
- `SendScheduler`: bounded rendering, request concurrency, fair admission and result routing.
- `RateLimiterInterface`: non-blocking acquire decision with token cost and next eligible time; file and Redis adapters.
- `QuotaProvider`: scoped account snapshot, refresh coordination, pause state and conservative budget/headroom.
- `RetryPolicy`: explicit classification, backoff, age/attempt limit, and ambiguous-outcome handling.
- `SendOutcomeStore` plus retry outbox/dispatcher: durable recipient state and recoverable publication.
- `FeedbackInbox` / handler: authenticated ingestion, durable deduplication, and Mautic updates.
- `CertificateProvider`: bounded certificate retrieval/cache used by the maintained AWS validator.
- Diagnostics and optional metrics sink with a low-overhead default.

Do not put blocking `usleep()` or remote token acquisition inside a lazy iterator/CommandPool callback while outstanding HTTP transfers need that same thread to progress. Choose a tested scheduler integrated with the supported Guzzle handler, or use bounded dispatch rounds as an intermediate implementation. Resolve timer/HTTP progress behavior in a focused integration spike before promising a fully rolling implementation. AWS supports lazy command iterators, but laziness alone does not make blocking admission asynchronous. [AWS promises/pools](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_promises.html)

Use supported APIs across the actual Mautic 5/6/7 dependency matrix. Features shown in current Symfony documentation are candidates, not proof that every supported version exposes them.

## 4. Implementation phases and PRs

Effort is relative: S = localized fix, M = component/integration change, L = stateful architecture. Each PR includes its meaningful tests and documentation. The order below avoids making a performance change depend on unimplemented failure guarantees.

### Phase A — Establish a reliable baseline

**PR A1 — Baseline, instrumentation and benchmark fixtures (M)**

- Prepare implementation work from upstream 1.0.41; re-fetch and review any newer upstream commits before editing.
- Repair Composer test commands and the missing coding-style configuration; add supported-version CI using dependency resolution for valid PHP/Mautic combinations.
- Capture per-stage timings: dequeue/deserialization, context setup, rendering, limiter wait, HTTP, persistence, feedback authentication, contact lookup and update.
- Add deterministic clock/sleeper/client seams and a test HTTP server capable of latency, throttling, rejection, disconnection and acceptance-with-lost-response scenarios. Simple immediate SDK mocks alone cannot demonstrate real network concurrency.
- Build fixtures for transactional and tokenized sends, Unicode addresses, attachments, Cc/Bcc, missing metadata, dynamic headers, tracking and unsubscribe links.
- Produce repeatable JSON/CSV benchmark output including revision, resolved dependencies, machine resources, worker count, warmup, measurement duration, sample count and payload distribution.

Done: baseline runs are reproducible; fixture correctness is established; memory/latency measurements distinguish plugin work from Mautic/queue costs. Do not delay small correctness fixes until the entire benchmark matrix exists.

**PR A2 — Payload preservation and callback response correctness (S/M)**

- Preserve fields added by addSesHeaders() when building metadata-free raw payloads, including X-EMAIL-ID tags and configuration sets.
- Preserve valid List-Unsubscribe when no replacement token exists; verify interaction with Mautic's one-click headers and endpoint behavior.
- Validate callback JSON shape before array access; propagate nested processing failures; report rejected subscription URLs as errors.
- Keep existing SNS signature/topic validation and the already-fixed notificationType/eventType fallback.
- Correct README GetAccount permission guidance and add regression cases that traverse the full conversion/callback path.

Done: all supported payload options survive conversion; malformed callbacks are controlled responses; recoverable infrastructure failures have retryable handling. Avoid altering established accepted/delivered semantics accidentally.

**PR A3 — Client and configuration correctness (M)**

- Separate client identity (region plus credential-provider/configuration identity) from quota identity (AWS account plus region).
- Prevent same-region DSNs with different credentials from reusing the wrong client. Do not log/cache raw secrets as keys.
- Validate missing password before sanitizer; validate positive bounded rate, batch and concurrency settings, including non-finite/overflow values.
- Support role/default-provider-chain credentials alongside existing static-key DSNs. Let the provider refresh temporary credentials.
- Replace manual region allowlisting with supported SDK endpoint resolution and actionable validation errors.

Done: tests cover two accounts in one region, two regions, multiple IAM users sharing an account budget, and credential refresh. Existing DSNs continue working.

### Phase B — Correct rate accounting and durable recovery

**PR B1 — Shared rate contract and retry classification (M)**

- Extract the existing file bucket behind a testable admission interface; retain short locks outside network work.
- Charge actual To/Cc/Bcc destination cost for every explicit attempt; define behavior for a message whose cost exceeds burst capacity without splitting mail in a way that changes recipients' visible content.
- Coordinate SDK/plugin retries. Preferred first design: one explicit retry owner for sends, with SDK automatic send retries disabled on the relevant client or commands only after verifying supported configuration and error propagation. Control-plane retries remain separately configured.
- Distinguish definite rejection, account/configuration failures, safe retry candidates, and potentially accepted requests with lost responses. Not every network error is safely retryable.
- Apply bounded exponential backoff with jitter, attempt/age limits, cancellation and shared account pause state.

Done: initial plus retry traffic respects the configured token-bucket burst/rate envelope; permanent errors do not loop; no case requests impossible tokens indefinitely. Keep correctness tests for limiter store failures occurring after earlier recipients succeeded.

**PR B2 — Recipient ledger, retry outbox and replay (L)**

- First inspect Mautic producer/handler/statistics contracts per supported major. Select the hook that can assign a stable logical send ID before serialization; campaign/contact alone is insufficient because intentional repeated sends must remain possible.
- Proposed durable state: logical send ID, recipient identity, content/revision reference, current submission state, attempt count, next attempt time, lease/fencing version, SES MessageId and last classified error. Track delivery outcomes separately from submission state.
- Proposed submission states: pending, leased, accepted, retry_due, terminal_failed, ambiguous. Persist transitions with uniqueness/conditional updates so concurrent workers cannot claim the same ready attempt.
- Store known failures and pending retry publication in one transaction. Dispatch from an outbox so a database commit followed by a queue outage does not lose recovery work.
- Return from the enclosing job only after each recipient is durably accounted for. A later queue redelivery skips accepted/terminal entries and does not blindly replay the original batch.
- Define immutable-content versus rerender semantics; use bounded, retained payload storage or immutable references so a retry cannot silently send edited campaign content. Recheck current DNC/suppression eligibility immediately before retry admission.
- A worker can die after SES accepts but before persistence. An expired lease/fence cannot unsend mail: mark uncertainty, reconcile where feedback permits, and expose a policy/operator path. Do not promise exactly-once submission. SendEmail has no client idempotency-token parameter.
- Batch safe local persistence work where beneficial, but keep transactions short and never hold database locks across AWS calls. Retain enough state for queue redelivery windows; archive/prune outcomes in bounded jobs.

Done: known successes never replay in deterministic fault tests; failures remain recoverable; all ambiguous attempts are visible; recovery operations preserve logical send identity and statistics. Include queue-redelivery, outbox restart, DB outage, and kill-after-acceptance cases. This state model must land before long retries leave workers or new concurrent scheduling ships.

### Phase C — Send faster with bounded resources

**PR C1 — Lazy payload generation and immutable context (M)**

- Feed the existing generator through a bounded buffer instead of accumulating the full commands array.
- Resolve sender/reply-to/configuration-set/static headers once per logical send into immutable values; keep recipient-specific fields isolated.
- Configure maximum buffered recipients, maximum rendered bytes, and maximum in-flight requests separately. Account for one oversized message and temporary MIME/SDK encoding copies when defining the memory budget.
- Release completed payload references, exceptions and closures promptly. Existing Mautic metadata can still scale with queue batch size; cap that independently and measure it separately.
- Preserve token ordering and replacement semantics; optimize repeated token-key preparation only when fixtures and profiling justify it.

Done: recipient content stays equivalent and rendered-buffer memory is bounded; large input batches no longer require all MIME strings to exist simultaneously. Publish before/after memory and time-to-first-send.

**PR C2 — Rolling admission and removal of redundant throttling (M/L)**

- Complete the scheduler/handler integration spike from section 3. Keep a bounded pool busy as requests finish; observe rate permits and worker cancellation before admitting each request.
- Move delayed known-failure retries to the durable retry path from B2. Keep request timeouts explicit and account for uncertainty when cancellation interrupts an active send.
- Benchmark concurrency using `target requests/sec × observed latency` as an initial estimate, then cap by memory, sockets and rate headroom. Optional adaptive concurrency must be bounded and stable under throttling; do not conflate concurrency with the send quota.
- Disable the parent's one-call/sec limit only after every active path is covered by the shared budget. Preserve a compatibility switch during rollout.
- Validate queue visibility/redelivery and graceful-shutdown settings against maximum job runtime; add version-supported keepalive only where available. A sender process should not continue issuing requests after losing its work lease.

Done: slow requests do not create whole-batch barriers; transactional jobs exceed the old one-call/sec ceiling when quota permits; no increase in rate violations, content errors, or untracked outcomes. [Symfony throttle implementation](https://github.com/symfony/mailer/blob/6.4/Transport/AbstractTransport.php)

**PR C3 — Profile-driven rendering and network tuning (M, conditional)**

- Use CPU/allocation profiles from C1/C2 to choose individual changes to token handling, MIME preparation, static address/header construction, and attachment handling.
- Cache only immutable shared material; never share mutable personalized Email instances or reuse another recipient's tracking identifiers. Avoid unbounded cross-campaign caches.
- Measure connection reuse and tune connection/request timeouts; confirm the chosen async handler actually makes concurrent requests in each supported runtime.
- Reduce high-volume success/debug logs to counters/sampling, with useful per-failure correlation retained.

Done: each optimization has before/after measurements and semantic equivalence tests. Skip changes whose gains are below measurement noise or whose complexity outweighs their benefit.

### Phase D — Coordinate hosts and keep feedback fast

**PR D1 — Redis limiter and quota refresh (L)**

- Add an optional Redis implementation with atomic refill/debit and server time. Include account/region scope and deployment configuration version; prevent workers with conflicting rate/burst settings from silently racing.
- Define account-group discovery/configuration once per configuration lifecycle; do not call STS per send or require extra permissions without documenting them. Support explicit group IDs for deployments that already know the account boundary.
- Preserve file support for a single shared filesystem and move coordination state outside disposable cache. On store outage, pause/defer using durable state; do not silently fall back to independent per-worker limits.
- Persist no future token reservations initially. If limiter traffic becomes material, measure small bounded reservations with fairness/expiration, and accept conservative token loss on crash rather than accidental reuse.
- Refresh MaxSendRate, rolling quota usage and sending status with single-flight coordination and jitter. Preserve last-known-good values on failure, with an explicit maximum-staleness policy.
- Manual rate is a cap when actual quota is known. Track own admissions conservatively, reserve headroom, and reconcile with AWS; other account senders and delayed quota data mean local prediction alone cannot guarantee exact remaining daily quota.
- Pause/adapt after throttling and quota/account exhaustion. Treat fractional rates and burst capacity explicitly rather than silently flooring positive rates to zero.

Done: one budget spans hosts, independent accounts/regions are isolated, quota changes affect existing workers, cache clears cannot split the budget, store outages do not cause unrestricted sends, and control-plane refresh does not stampede AWS.

**PR D2 — Certificate cache and durable feedback inbox (L; cache can be an earlier standalone S/M PR)**

- Inject a certificate provider into the AWS validator. Cache retrieved certificate material by trusted exact URL using bounded TTL/certificate validity and cache-size limits; suppress concurrent duplicate fetches.
- Preserve URL validation, HTTPS verification, topic allowlist and signature verification on every request. Use explicit fetch timeouts and controlled redirects. Certificate rotation/expiry must refresh correctly; unavailable trusted certificate retrieval must be distinguished from a cryptographically invalid signature for retry behavior without accepting either.
- Store the verified envelope durably, then acknowledge. Deduplicate at least by topic plus SNS MessageId and make recipient side effects idempotent under consumer redelivery.
- Process contact changes in bounded units using supported Mautic models. Preserve model events and per-email statistics; do not replace these with direct SQL merely to gain speed.
- Distinguish API acceptance, delivery, delays, rejection, bounces and complaints. Map by SES MessageId plus the existing Mautic tag/header fallback. Handle events arriving before a corresponding send-result transaction has committed.
- Maintain a fast suppression path or shared admission check so feedback backlog does not allow large numbers of additional sends to newly suppressed contacts.

Done: repeated callbacks sharing a certificate do not repeatedly download it within valid cache lifetime; invalid signatures still fail; duplicate/reordered feedback is harmless; committed events replay after failure; feedback latency and suppression lag are measured separately. [AWS validator source](https://github.com/aws/aws-php-sns-message-validator/blob/master/src/MessageValidator.php)

### Phase E — Operations and optional next-level throughput

**PR E1 — Metrics, diagnostics and operating guide (M)**

- Ship low-cardinality counters/histograms for accepted recipients, outcomes, retry reasons, limiter wait, HTTP latency, render CPU, queue age, memory, certificate fetches and feedback/suppression lag. IDs/addresses belong in controlled diagnostic records, not metric labels.
- Proposed `ses:health` command: effective client/region/account group, resolved quota and age, limiter backend, writable paths/connectivity, SNS allowed topics, queue/dead-letter depth and oldest age. Make network probes explicit and avoid sending mail during health checks.
- Add recovery/replay commands from B2 with filters and dry-run; replay must respect suppression and stable send IDs.
- Fix README IAM guidance (`GetAccount`, not only `GetSendQuota`), worker settings, supported runtime matrix, region handling, installation placeholders and stale comments. Resolve licensing inconsistency with the maintainer. Surface service-registration exceptions rather than swallowing them.
- Provide outcome/payload retention, cleanup, credential rotation, store-outage, quota-exhaustion, and callback-failure runbooks.

Done: operators can distinguish quota-bound, CPU-bound, HTTP-bound, storage-bound and feedback-bound deployments; diagnostics expose no credentials; replay does not bypass normal rate/suppression rules.

**PR E2 — Transactional priority and campaign safeguards (M/L)**

- Separate urgent and bulk scheduling, reserve a configurable budget share, and allow borrowing unused capacity without starving either class.
- Add campaign fairness, explicit pause/resume and configurable soft-bounce count/window/cooldown policy integrated with actual Mautic eligibility.
- Base campaign safeguards on deduplicated complaint/bounce observations and feedback lag. Avoid automatic cross-region/account spillover that bypasses reputation controls or unknown quota scopes.

Done: urgent queue latency stays within the chosen service target during bulk load, every class respects one shared budget, and new DNC state reaches admission promptly.

**PR E3 — Optional SES bulk-template path (L, experimental)**

- First complete the bounded study in [SES_BULK_TEMPLATE_RESEARCH.md](SES_BULK_TEMPLATE_RESEARCH.md): compare shared-template translation with locally rendered body wrappers, establish real batch sizes under request/data limits, and verify actual SES rendering parity. The historic AWS header restriction was removed; no automatic Mautic/plugin compatibility fix was found.
- Benchmark whether raw API overhead or rendering remains significant after C1–C3. If already quota-bound with acceptable resource cost, defer this work.
- Define a narrow eligibility contract for template reuse: body equivalence, per-recipient substitution, tracking URLs, headers, unsubscribe semantics, dynamic content, attachments and Mautic extension hooks must remain correct. Unsupported cases use raw sends.
- Use current SES SendBulkEmail template capabilities with a bounded entry count and SDK-version compatibility checks. Handle each returned entry status independently; HTTP 200 does not mean every entry succeeded.
- Store per-entry outcomes/MessageIds, rate-charge recipients, retain account-region coordination, and handle whole-request ambiguity without replaying known accepted entries.
- Keep disabled by default until parity fixtures, integration tests, and a measured CPU/network/API-call benefit justify enabling it.

Done: compatible messages preserve recipient-visible/tracking behavior and consume fewer API requests or less CPU/bandwidth per accepted recipient. This is not a promise to bypass SES recipient quotas. [SES bulk API](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendBulkEmail.html)

### Phase F — Newsletter features beyond sending speed

These can be delivered incrementally on the foundations above. Start with a report/CLI backed by indexed aggregates; add a Mautic view after the data contracts are stable. Do not require a separate analytics platform for 150k recipients.

**PR F1 — Campaign delivery report and provider diagnostics (M/L)**

- Reuse the existing Mautic email ID and add a stable newsletter-run ID so repeated sends of the same email have separate reports.
- Track queued/eligible, submitted/accepted, delivered-to-server, delayed, suppressed, permanently failed and ambiguous submissions, with definitions that distinguish state from event counts.
- Show effective acceptance rate and projected time to finish submission, recalculated from remaining eligible work and recent observations. Do not predict inbox arrival from API throughput.
- Provide indexed recipient drilldown: send time, SES MessageId, latest delivery status, bounce/delay reason and recovery eligibility. Default to aggregate views; paginate personal data and apply Mautic permissions/retention.
- Group initially by recipient domain. Provider grouping for custom domains requires cached/maintained MX mapping; label unknown groups rather than assuming all custom domains are independent mailbox providers. Avoid DNS lookups per email in the send loop.
- Ingest DeliveryDelay/Reject/Rendering Failure in addition to existing bounce/complaint events, and surface delayed feedback/missing attribution. Delivery means recipient-server acceptance, not inbox placement or a human open.
- Use incremental aggregates indexed by run, state, domain and time; dashboard polling must not repeatedly scan 150k recipient rows. Reconcile aggregates against the ledger asynchronously.

Done: after a campaign, an operator can explain what happened to recipients without parsing logs, and reports distinguish delayed delivery from failed submission. Correlation handles feedback arriving before the HTTP send response is recorded. [SES event fields](https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-contents.html)

**PR F2 — SES suppression reconciliation and late eligibility checks (M)**

- Add a paginated, restartable reconciliation job for the relevant SES account/region suppression list, with dry-run counts and a report of contacts Mautic still considers sendable.
- Cache/persist the matching suppression set locally and reconcile incrementally plus occasional complete scans; do not make an AWS lookup for every recipient during sending.
- Preserve suppression source, reason, scope and observation time. Keep original AWS email casing for API management while using a documented contact-matching policy consistent with Mautic.
- Apply confirmed bounce/complaint suppressions through Mautic's supported model and recheck the latest relevant DNC state before admitting initial/retry sends. Resolve existing Mautic send-time checks before adding redundant queries.
- Never infer renewed consent from removal/absence on the AWS list or automatically remove a Mautic unsubscribe. If configuration-set/tenant suppression overrides are in use, account for their effective scope rather than blindly treating the account list as universal.
- Observe the race between the final eligibility check and request dispatch; minimize it and expose maximum lag, without promising to recall an already-submitted email.

Done: a lost callback is repaired by reconciliation; an unsubscribe received during the 31-minute run can prevent later unsent work; repeated syncs are idempotent; valid consent/DNC decisions are not undone. SES-suppressed submissions can still consume daily quota, making skipped work useful even when sending speed is sufficient. [AWS suppression behavior](https://docs.aws.amazon.com/ses/latest/dg/sending-email-suppression-list.html)

**PR F3 — Preflight and exact payload preview (M)**

- Proposed read-only `ses:preflight` checks: actual rate and remaining rolling quota, account sending status, sender identity, effective configuration set, SNS topics/required event types, callback freshness, and payload-size budget. Missing optional inspection permissions produce an explicit unknown result rather than a false pass.
- Show a dry-run sample of the fully rendered outgoing MIME and SES fields for representative recipients: sender/reply-to, subject, tags, tracked links, unsubscribe headers, text/HTML and attachments. Use bounded local inspection/export with permissions and sensitive-data handling appropriate to those real recipients.
- Compare candidate template-mode output against the raw path and make unresolved personalization obvious. Do not claim that a payload preview predicts inbox placement.
- Report eligible/suppressed counts and estimated submission duration using existing Mautic segment data plus transport eligibility. Avoid a second inconsistent segment engine.
- Optional explicit test-send mode targets a user-selected seed/simulator address; read-only preflight itself never sends to recipients.

Done: operators can diagnose common SES-specific misconfiguration before launching 150k recipients and can inspect what the transport would actually send.

**PR F4 — Run controls backed by durable progress (M after B2)**

- Expose pause/resume at admission boundaries using a durable run state observed by every worker; already accepted/in-flight messages cannot be recalled.
- Show resumable progress, terminal failures and ambiguous sends separately. Offer a dry-run failed-only replay with reason filters and counts; do not automatically retry delivery delays already being retried by SES.
- Preserve original run/content identity and check current suppression before recovery. Mark deliberate resend as a new logical operation so deduplication does not suppress intentional user actions.
- Add a reconciliation report for unfinished runs after deployments or worker loss and a bounded cleanup process for old outcomes/payloads.

Done: stopping workers mid-campaign can be recovered from without resubmitting known accepted recipients; uncertain cases remain visible for an explicit policy decision.

**PR F5 — Optional delivery-aware admission pacing (M/L after F1)**

- Begin with observation and recommended actions. Use provider/domain delay types, bounce/complaint rates, minimum sample sizes, rolling windows, hysteresis and cooldowns before automating a response.
- Explicitly distinguish provider/server/IP delivery trouble from isolated mailbox-full events or SES-internal failures. Slow/pause only affected *future submissions*; SES remains responsible for retrying mail it already accepted.
- Keep total admissions under the existing 80/s budget and redistribute unused opportunity to other ready destinations fairly. Never bypass the SES account budget or attempt automatic alternate-account delivery.
- Make policy opt-in and reversible, with a visible explanation and an audit record. The useful outcome may be better delivery stability rather than a shorter campaign.

Done: replayed representative event streams trigger bounded, explainable policy actions without oscillation or duplicate sends. No automatic thresholds ship until enough real observations exist. This is transport delivery control, not engagement-based campaign scheduling.

## 5. Proposed configuration contract

Names below are proposals, not options supported by the current plugin. Final placement must match supported Mautic configuration APIs. Redis connection credentials belong in secret-backed application configuration, not in diagnostic DSN output.

| Setting | Purpose / compatibility rule |
| --- | --- |
| `ratelimit` | Retain existing option; document capped-by-known-quota semantics and migration from override behavior. |
| `batchmultiplier` | Retain existing option during transition; derive legacy batch size only when explicit batch size is absent. |
| `batchsize` | Maximum recipients represented by one queue job, independent of send rate. |
| `concurrency` | Maximum in-flight requests per worker; conservative fixed value before any adaptive mode. |
| `maxbufferbytes` | Cap rendered payload buffer; document encoding overhead and oversized-message policy. |
| `limiter` / `quota_group` | File or Redis backend; stable account/region group shared by all participating senders. |
| `burst` | Explicit burst allowance, validated with rate and maximum request recipient cost. |
| Retry age/attempt limits | Bounded recovery with explicit ambiguous-send policy and failure-store retention. |
| Quota refresh/staleness | Refresh cadence, jitter, single-flight lease and maximum stale-data policy. |
| Feedback backend/retention | Durable inbox and deduplication horizon covering provider retries/replays. |
| Priority reserve | Optional urgent-traffic share; disabled until scheduling is implemented. |
| Template mode | Explicit experimental opt-in with raw fallback. |

## 6. Benchmark and fault matrix

Run focused cases first; do not make the full Cartesian product a prerequisite for every PR.

| Dimension | Cases |
| --- | --- |
| Workload | Single-recipient transactional jobs; personalized campaign; mixed traffic. |
| Recipient count | 1,000 / 10,000 for fast iterations; **150,000** for the representative campaign; same distribution for baseline and candidate. |
| Rendered size | 20 KB / 200 KB HTML and text; attachment fixtures around 1 MB / 10 MB. |
| Rate | **80 recipients/sec** primary synthetic case; optional 200 / 1,000 future stress cases; verified account quota for live checks. |
| Workers / hosts | 1 / 4 / 16 workers; one host and two independently cached hosts. |
| HTTP latency | 50 / 200 / 500 ms plus a long-tail case with 1% of requests delayed 2 seconds. |
| Failures | Throttling bursts, terminal validation errors, 5xx, connect failures, lost response after acceptance. |
| Infrastructure | Redis unavailable, read-only file store, corrupt bucket, DB outage, queue outage/redelivery, process kill, clock anomaly, quota decrease. |
| Feedback | Duplicate/reordered envelopes, rotation/expiry of signing certificate, slow cert endpoint, invalid signatures, consumer outage and replay. |

Use at least three repeated timed runs after warmup for performance comparisons and publish variability. Keep payloads seeded and repeatable. Use a real local HTTP fault server for scheduler tests, process/container boundaries for distributed tests, and an opt-in SES mailbox-simulator/staging verification appropriate to account quota. Never treat a simulator or mock as a production throughput measurement.

Provisional release gates, to calibrate with the baseline:

- User-specific target: preserve the current effective throughput on the representative 150k campaign while reducing measured peak memory, CPU time, request overhead or required worker count. Establish the actual baseline before setting a numerical savings target; no regression in recovery or personalization is acceptable to achieve the savings.
- Deterministic healthy harness: at least 90% of configured rate when its measured render/network/storage capacity supports that rate; otherwise identify the limiting resource. Report recipients accepted, not attempted requests.
- Fixed recipient metadata and fixed buffer/concurrency: rendered-buffer memory remains within the configured budget plus documented per-message/transient overhead. Report total RSS separately.
- Long-tail latency: no unnecessary full-batch barrier; ready work continues while another request is slow.
- Fault runs: every logical recipient has a durable outcome or recoverable state, and known accepted recipients are not automatically resubmitted. Count ambiguous cases explicitly instead of hiding them in success/failure totals.
- Limits: actual admitted traffic respects configured burst/rate bounds, and retries never take an unaccounted path.
- Feedback: propose normal-load p95 verified-to-durable-ingest below 250 ms with a warm certificate cache and p95 ingest-to-suppression below 5 seconds; validate hardware/Mautic feasibility before treating these as commitments.
- Compatibility: existing tokenized MIME, attachments, tracking, headers, callbacks and supported-version test cases pass.
- Durability overhead: report CPU/SQL/bytes per recipient introduced by the ledger/inbox; tune without weakening required crash semantics.

## 7. Rollout and rollback

1. Land small correctness fixes and instrumentation first. Establish current resource usage and failure rates.
2. Add schema/state components using additive migrations and tested cleanup/retention. Feature flags must not create overlapping send ownership.
3. Canary durable recovery and streaming on an isolated queue/account group; compare outcomes and resource use. Scale concurrency only after fault tests pass.
4. Migrate limiter backends by stopping admission and draining outstanding work before switching all workers in the quota group. Do not run file and Redis workers independently against the same account quota.
5. Deploy feedback ingestion/consumers together; acknowledge only after storage succeeds. Monitor suppression lag and pause bulk admission if the documented threshold is crossed.
6. Roll out priority and optional template mode last, with raw-path equivalence and backend-specific metrics.

Rollback may disable an optimization, but must continue honoring the durable send ledger, suppression state, and shared quota ownership. Older senders that ignore new recipient state can replay accepted recipients; drain/migrate pending work before reverting across that boundary. Do not drop additive tables or discard retry/inbox records during rollback.

## 8. Coverage of the original improvement list

| Review item | Planned work |
| --- | --- |
| Durable recipient recovery | B2, E1 |
| Retry pacing/classification | B1, B2, C2 |
| Distributed scoped limiter | B1, D1 |
| Bounded rendering/concurrency | C1, C2, C3 |
| Payload/header preservation | A2 |
| Quota/account refresh | D1, A3 |
| Durable/deduplicated feedback | A2, D2 |
| Outcome tracking/metrics | B2, D2, E1 |
| Client isolation/role credentials | A3 |
| Fault/compatibility/load tests | A1 and acceptance tests in every PR |
| Priority/fairness/deliverability | E2 |
| IAM/docs/diagnostics | A2, E1 |

For this user: start with a focused A1 baseline and A2 correctness fixes; add certificate caching as an early performance PR. B1/B2 enable trustworthy F1 reports and F4 resume/recovery. C1 measures resource savings at the existing 80/s. F2/F3 add newsletter-specific value without requiring more servers. Complete C2/C3 or experiment with E3 only where measurements justify the work. D1 is deferred until independent hosts are needed; retain its quota-refresh improvements for the existing deployment. F5 follows usable delivery observations.

Suggested user-facing milestones:

1. **See the run:** read-only SES preflight, accurate acceptance/delivery definitions, basic run metrics and baseline resource report.
2. **Recover the run:** durable recipient outcomes, failed-only recovery, pause/resume and complete delivery report.
3. **Use fewer resources:** streaming, immutable context, cached certificates, and measured concurrency/rendering changes at the same 80/s.
4. **Keep the list clean:** suppression reconciliation, late eligibility checks, feedback-lag visibility and optional domain/provider diagnostics.
5. **Explore a bulk path:** eligibility/parity prototype, measured request/CPU savings, raw fallback and guarded opt-in.

## 9. Review method and verification limits

The local review-agent skill was read and used for the source-review portion: inspect actual changed paths and call sites, distinguish regressions from pre-existing behavior, and avoid speculative findings. This plan intentionally also contains new features and profiling hypotheses; those are not presented as regressions introduced by upstream 1.0.41. No subagents or third-party skills were installed.

The previous review checked all 13 upstream PHP files with php -l and validated Composer metadata. This planning pass inspected the send loop, context/header setup, factory, authenticator and test configuration, plus primary AWS/Symfony sources. No new runtime benchmark or Mautic integration test has been executed. All target numbers above are proposed acceptance criteria or labeled analytical estimates.

Primary references:

- [Pinned plugin baseline](https://github.com/pm-pmaas/etailors_amazon_ses/tree/46b8ddb)
- [AWS sending quotas](https://docs.aws.amazon.com/ses/latest/dg/manage-sending-quotas.html)
- [AWS SendEmail API](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html)
- [AWS GetAccount API](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_GetAccount.html)
- [AWS PHP promises and command pools](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_promises.html)
- [AWS PHP client configuration](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_configuration.html)
- [AWS SNS message validator](https://github.com/aws/aws-php-sns-message-validator/blob/master/src/MessageValidator.php)
- [AWS SendBulkEmail API](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendBulkEmail.html)
- [Symfony 6.4 AbstractTransport](https://github.com/symfony/mailer/blob/6.4/Transport/AbstractTransport.php)
- [Symfony Messenger documentation](https://symfony.com/doc/current/messenger.html)
