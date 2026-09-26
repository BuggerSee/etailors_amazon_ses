Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]
### Added
- Experimental bulk sending with shared SES templates, off by default. With the DSN option `bulk=auto`, eligible emails are sent with `SendBulkEmail`: one inline template per request, each recipient's resolved Mautic tokens as replacement data and up to 50 recipients per request (`bulk_batch_size`, 1 to 50, default 50; `bulk_concurrency`, 1 to 10, default 2). Every recipient of an email is recorded in a delivery outbox in one transaction before the first request, charged against the shared token bucket and classified from its own SES result; once recorded, later failures are logged and left to the outbox's retry instead of failing the email. A request carries at most `ratelimit` / `bulk_concurrency` recipients, so the requests in flight never exceed one second of the send rate. Emails and recipients that cannot use a shared template fall back to raw sending before anything is submitted; a `Return-Path` header becomes the SES feedback forwarding address. SES events tagged with `mautic_delivery_id` update the outbox. An email without its own From address keeps the From address Mautic resolved, also when Mautic sets a `Return-Path` (with `bulk=off` the plugin still takes the envelope sender, which is then the `Return-Path` address). The outbox is scoped to the SES region, so rotating the access key keeps every recorded recipient. See the README section "Bulk sending with shared SES templates (experimental)".
- `mautic:ses:bulk` console command with the actions `install`, `status`, `retry`, `sync-stats` and `prune` (deletes finished outbox rows after a retention period, 30 days by default).
- Plugin migration `Version_1_0_42`, which creates the outbox tables `ses_bulk_contents` and `ses_bulk_deliveries` on `mautic:plugins:reload` once the plugin version is raised.
- `endpoint` DSN option to replace the regional SES API endpoint with an absolute http(s) URL (URL-encoded in a DSN string).
- Fake SES server (`Tests/E2E/fake-ses-server.php`) and an offline end-to-end harness (`Tests/E2E/offline/`) for local runs without AWS; see `docs/SES_E2E_TESTING.md`.

### Changed
- Inline retries on the raw path now charge the shared token bucket, like first attempts.
- The shared token bucket no longer stores a burst allowance. Its balance only records debt, and a submission takes its tokens first and then waits until the debt is repaid. Before, an idle bucket held one second of the rate, so the first second of a send could submit up to twice `ratelimit`, which the SES console reported as sending rate utilization above 100 %. Sending is now paced at `ratelimit` from the first request on, across all workers.
- Errors from a nested SNS `Notification` message now propagate to the callback's HTTP response instead of being answered with success.
- SES event types `Send`, `Reject` and `Rendering Failure` are accepted by the callback and no longer logged as unknown.
- The SNS callback downloads the signing certificate through Symfony HttpClient with a 5-second timeout and caches it for an hour. When the certificate cannot be downloaded, the callback is now answered `503`, which SNS retries, instead of `403`, which made SNS drop the bounce or complaint for good; rejected callbacks are logged with the reason.
- `aws/aws-sdk-php` requirement raised to `^3.325.1`, the first version whose SES v2 model supports inline template content.
- The bulk outbox keeps a recipient's request data (and a raw recipient's message) only until the recipient is `accepted`, `rejected` or `unknown`, leaving about 1 KB of bookkeeping per row; it saves recipients with up to 200 rows (and about 4 MB of request data) per `INSERT`, and `ses_bulk_deliveries` gets a `(state, updated_at)` index, which `mautic:ses:bulk install` and the migration `Version_1_0_42` also add to existing outbox tables.

## [1.0.41] - 2026-09-25
- `CallbackSubscriber` now unescapes Mautic's `%%` in `mailer_dsn` before parsing it, so an `sns_topic_arn` DSN option saved through the Email settings UI (stored as `arn%%3Aaws%%3A...`) matches the SNS `TopicArn` instead of decoding to `arn%:aws%:...` and rejecting every callback with 403.

## [1.0.40] - 2026-09-21
### Security
- Authenticate SNS webhook signatures with AWS's maintained validator and require an exact allowed topic ARN before processing feedback.

## [1.0.39] - 2026-09-07
### Fixed
- Merged Fix per-email bounce attribution when SES omits headers- #154
  https://github.com/pm-pmaas/etailors_amazon_ses/pull/154.

## [1.0.38] - 2026-08-31
### Fixed
- Fixed the release branch metadata so the plugin reports version `1.0.38`.

## [1.0.37] - 2026-07-24
### Fixed
- Changed DNC channel value from `soft bounce` to `soft_bounce` to fix `RouteNotFoundException` in Mautic reports. **Note: requires manual SQL migration: `UPDATE lead_donotcontact SET channel = 'soft_bounce' WHERE channel = 'soft bounce';`**
- Fixed SES rate limit token bucket cache permission errors by returning a clear transport error instead of crashing with a `flock()` `TypeError` when the Mautic cache directory is not writable.

## [1.0.36] - 2026-06-10
### Fixed
- Fixed missing `eventType` fallback in `CallbackSubscriber.php` for the `Notification` case: added null-coalescing fallback `$message['notificationType'] ?? $message['eventType'] ?? 'unknown'` to handle SNS notifications that use `eventType` instead of `notificationType`.

## [1.0.35] - 2026-05-21
### Fixed
- Fixed multi-region SES support: `AmazonSesTransportFactory` now caches `SesV2Client` instances per region instead of a single shared client, preventing the first configured region from being silently reused for all subsequent transports with different regions.

## [1.0.34] - 2026-05-21
### Fixed
- Re-released fix from 1.0.33 branch that was missing from the 1.0.33 tag: mailer DSN not being recognized in worker/messenger context due to static properties in `AmazonSesTransportFactory`.

## [1.0.33] - 2026-05-21
### Fixed
- Fixed mailer DSN not being recognized in worker/messenger context by converting static properties and methods in `AmazonSesTransportFactory` to instance-based, ensuring each process gets its own properly initialized factory.
- Fixed cache permission errors by moving the SES send quota cache file from the `cache` directory to the `tmp` directory.
- Removed unused `$amazonclient` constructor parameter from `AmazonSesTransportFactory`.

## [1.0.32] - 2026-04-22
### Added
- Shared file-based token bucket for cross-worker SES rate coordination.
- New DSN option `batchmultiplier` (default 10) to control contacts per queue message.
- Inline retry with exponential backoff (1s, 2s, 4s) within `doSend()`, replacing Symfony Messenger retry to prevent metadata loss.
### Changed
- Improved throughput pacing by sending emails in micro-batches (ceil(rate/10)) via `CommandPool`.
- Moved rate limiting to sit between actual SES API calls rather than payload building.
- Updated `getMaxBatchLimit()` to return `rate` × `batchmultiplier`.
### Fixed
- Fixed `processFailures()` throwing an exception which caused Symfony Messenger to retry entire batches and result in duplicate sends.
- Fixed `throttle()` positioning to ensure effective rate limiting.
- Prevented throughput spikes above SES limit when using multiple workers by implementing shared rate limiting.

## [1.0.31] - 2026-01-24
### Added
- Mautic 7 compatibility.
### Changed
- Updated `composer.json` to support `mautic/core-lib` version `^7.0`.
- Maintained backward compatibility with Mautic 5 and 6.
- Ensured PHP 8.1 compatibility remains (Note: Mautic 7 itself requires PHP 8.2+).
- Internal alignment with Mautic 7 platform requirements.

## [1.0.30] - 2026-01-24
### Added
- Added Zurich (`eu-central-2`) region support.
### Fixed
- Fixed bug in updating soft bounce DNC entry logic in `CallbackSubscriber.php`.

## [1.0.29] - 2025-12-09
### Added
- Added `CHANGELOG.md` and `SECURITY.md`.
- Improved soft bounce handling with custom channel and labeling.
### Fixed
- Improved resilience in `CallbackSubscriber.php` when processing various SNS payload types.

## [1.0.28] - 2025-12-09
### Security
- Fixed a security issue by validating the Amazon SNS `SubscribeURL` endpoint. This ensures that only legitimate SNS subscription confirmation requests are accepted (mitigates SSRF).
### Added
- Added `eu-west-3` (Paris) region support.
### Changed
- Improved handling of special characters and IDN encoding in the "From" name using Symfony's `Address` class.

## [1.0.27] - 2025-11-20
### Added
- Added `eu-west-2` (London) region support.
### Fixed
- Fixed escaping of quotes in `FromEmailAddress`.

## [1.0.26] - 2025-11-15
### Changed
- Updated `README.MD` with detailed Composer installation instructions (using `-W` flag and VCS repository).

## [1.0.25] - 2025-11-10
### Added
- Added `composer/installers` requirement to ensure correct plugin installation directory.
### Changed
- Improved `composer.json` with `prefer-stable: true`.

## [1.0.24] - 2025-11-05
### Added
- Added example IAM user policy to `README.MD`.

## [1.0.23] - 2025-11-01
### Changed
- Updated `mautic/core-lib` version requirement to support `^6.0`.

## [1.0.22] - 2025-10-25
### Fixed
- Fixed `getAccount` method failure when `ses:GetAccount` action permissions are missing by adding a fallback to `DEFAULT_RATE`.
- Cleaned up default rate limit handling in `AmazonSesTransportFactory.php`.

## [1.0.21] - 2025-10-20
### Added
- Added `us-west-1` (N. California) region support.

---

Older changes may be documented in commit messages and release notes on the repository.
