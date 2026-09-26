# Mautic AWS SES Plugin with SNS Callback

This plugin provides integration between [Mautic 5, 6 and 7](https://www.mautic.org) and [Amazon SES](https://aws.amazon.com/ses/) for sending emails through AWS. It also integrates with [Amazon SNS](https://aws.amazon.com/sns/) for handling email feedback such as bounces and complaints via callbacks. (PHP >= 8.1 required; Note: Mautic 7 itself requires PHP 8.2)

This is a custom plugin inspired by the structure of:
- [mabumusa1/ses-plugin](https://github.com/mabumusa1/ses-plugin)
- [ts-navghane/sparkpost-plugin](https://github.com/ts-navghane/sparkpost-plugin)

Feel free to suggest improvements or provide feedback — this is my first Mautic plugin and community contributions are welcome.

---

## Features
- Send emails through Amazon SES using the API.
- Support for setting AWS regions and optional custom rate limits in the DSN.
- Integration with Amazon SNS to process bounces and complaints via callback.
- Built-in **rate limiting** to honor SES sending quotas.
- Dynamic **batch size** matching the current SES max send rate.
- Auto-fetch and cache your SES sending quota.
- Manual override of rate limit with `ratelimit` DSN option.
- Optional retry handling for partial email failures.

---

## Installation

### 1. Download and Install the Plugin

#### Install manual

1. Download or clone the repository to your Mautic plugins directory:

   ```bash
   cd /path/to/your/mautic/plugins
   git clone https://github.com/yourusername/mautic-aws-ses-plugin.git AmazonSesBundle
   ```

2. Clear Mautic’s cache:
   
   ```bash
   php /path/to/mautic/bin/console cache:clear
   ```

3. Go to **Mautic Settings > Plugins** and click the “Install/Update Plugins” button.

---

#### Install via Composer

If you prefer installing via Composer, run the following command from your Mautic root directory:

```bash
composer require etailors/mautic-amazon-ses:^1.0 -W 
```
Version number 

Then clear the cache and reload the plugins:

```bash
rm -rf var/cache/*
php bin/console mautic:plugins:reload
```

> **Note:**  
> The plugin will automatically install into `plugins/AmazonSesBundle`.

---

### 2. Configure Amazon SES Settings

1. In Mautic, navigate to **Settings > Email Settings**.
2. Select the newly installed **AWS SES** option.
3. In the **DSN** field, enter your connection string in the following format:

   ```text
   mautic+ses+api://<AWS_ACCESS_KEY>:<AWS_SECRET_KEY>@default?region=<AWS_REGION>&ratelimit=14&sns_topic_arn=<SNS_TOPIC_ARN>&bulk=off&bulk_batch_size=50&bulk_concurrency=2&endpoint=<URL_ENCODED_ENDPOINT>
   ```

   - Replace `<AWS_ACCESS_KEY>` and `<AWS_SECRET_KEY>` with your AWS credentials.
   - Replace `<AWS_REGION>` with your AWS region (e.g., `us-east-1`).
   - Optionally set `ratelimit` to override the SES max send rate manually.
   - Set `sns_topic_arn` to the exact SNS topic ARN used for feedback. The callback
     fails closed when no allowed topic is configured. For multiple topics, set
     `amazon_ses_sns_topic_arns` as an array in Mautic's local configuration.
   - Optionally set `bulk=auto` to send eligible emails with shared SES templates. `bulk=off` is the
     default and keeps raw sending. `bulk_batch_size` (1 to 50, default 50) and `bulk_concurrency`
     (1 to 10, default 2) only apply with `bulk=auto`. Read
     [Bulk sending with shared SES templates](#bulk-sending-with-shared-ses-templates-experimental)
     before enabling it.
   - Optionally set `endpoint` to an absolute `http://` or `https://` URL that replaces the regional SES
     API endpoint. In a DSN string, URL-encode it (for example `endpoint=http%3A%2F%2F127.0.0.1%3A4566`);
     as an option in the Email Settings form, enter the plain URL, because the form encodes option values
     itself. Leave it out to use the regional AWS endpoint.

4. Set the region in the `options` parameter, for example:

   ```text
   Label: region   Value: eu-west-1
   ```

![Amazon SES Integration](https://github.com/pm-pmaas/etailors_amazon_ses/blob/1.0.1/Assets/img/mautic-ses-dsn.png)

---

### 3. AWS SES Configuration

1. Ensure that you have verified your domain and email addresses in AWS SES.
2. Set up the appropriate IAM user with permissions to send emails via SES.  
   **Please make sure you create a new IAM user directly via IAM instead of upgrading an SMTP user with the permission: sending via SES API.**

   There are known issues when upgrading SMTP-only users — see: [issue #28](https://github.com/pm-pmaas/etailors_amazon_ses/issues/28).

Your IAM user must have permission to send and get account limits. Here’s an example policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSesSendingAndQuota",
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail",
        "ses:GetSendQuota"
      ],
      "Resource": [
        "arn:aws:ses:<region>:<account id>:identity/*",
        "arn:aws:ses:<region>:<account id>:configuration-set/*"
      ]
    }
  ]
}
```

---

### 4. Available Regions

```
af-south-1
ap-northeast-1
ap-northeast-2
ap-south-1
ap-southeast-1
ap-southeast-2
ca-central-1
eu-central-1
eu-north-1
eu-west-1
eu-west-2
eu-west-3
sa-east-1
us-east-1
us-east-2
us-gov-west-1
us-west-1
us-west-2
```

---

## SNS Callback Configuration

To receive feedback from Amazon SES regarding bounces and complaints, you need to set up Amazon SNS.

1. Go to your [Amazon SNS Dashboard](https://console.aws.amazon.com/sns/v3/home).
2. Create a new **Topic** (or use an existing one) for SES feedback.
3. Subscribe to this topic with an **HTTPS endpoint** using the following URL:

   ```text
   https://<your-mautic-instance-url>/mailer/callback
   ```

4. Ensure your topic sends notifications for bounces, complaints, and delivery status.
5. Ensure the exact topic ARN is configured as `sns_topic_arn` in the mailer DSN.
   The plugin verifies the AWS signature and topic before processing any callback.
6. For classic identity-based SNS notifications, enable **Include original headers** for bounce and complaint notifications on the verified SES identity. Mautic uses the `X-EMAIL-ID` header to attribute feedback to the email statistics. Configuration-set event publishing can use the `X-EMAIL-ID` message tag added by this plugin instead.
7. Test your callback configuration by sending test emails and reviewing Mautic logs to verify feedback is processed correctly.

---

## Batch Limit & Throttling

To avoid exceeding SES rate limits, this plugin automatically:

- Caches the current `maxSendRate` returned by AWS SES.
- Dynamically adjusts the batch size to match that rate.
- Throttles outgoing email API calls using `usleep()`.
- Allows overriding the send rate via `ratelimit` DSN option.

This prevents common errors like `TooManyRequests` while maximizing throughput.

---

## Bulk sending with shared SES templates (experimental)

With `bulk=auto`, the plugin sends an eligible email with SES `SendBulkEmail`. Each request carries one inline
SES template with the parts all recipients share (subject, HTML and plain text), and each recipient's tokens,
already resolved by Mautic (contact fields, tracked links, unsubscribe and web view links), as that recipient's
replacement data. One request carries up to 50 recipients. Every recipient is still charged against the same token
bucket as raw sending, so bulk sending saves requests and upload volume; it does not raise the SES sending quota.

`bulk=off` is the default and keeps the raw MIME sending of earlier versions.

### Options

| DSN option         | Values                               | Default | Meaning                                                                                                                                                                                     |
|--------------------|--------------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `bulk`             | `off`, `auto`                        | `off`   | `auto` sends eligible emails through shared templates; `off` sends raw MIME only.                                                                                                           |
| `bulk_batch_size`  | 1 to 50                              | `50`    | Maximum recipients per `SendBulkEmail` request. Requests are also limited to the effective send rate (`ratelimit` or the SES `MaxSendRate`) in recipients and to 1,000,000 bytes.           |
| `bulk_concurrency` | 1 to 10                              | `2`     | Requests one sending process (or one `retry` run) keeps in flight.                                                                                                                          |
| `endpoint`         | absolute `http://` or `https://` URL | not set | Replaces the regional SES API endpoint, for example with an SES VPC endpoint or the local fake server. URL-encode it in a DSN string; the Email Settings form encodes option values itself. |

Other values are rejected when the transport is created. Example:

```text
mautic+ses+api://<AWS_ACCESS_KEY>:<AWS_SECRET_KEY>@default?region=<AWS_REGION>&ratelimit=80&sns_topic_arn=<SNS_TOPIC_ARN>&bulk=auto
```

Clear Mautic's cache after changing the DSN.

### Requirements

- `aws/aws-sdk-php` 3.325.1 or newer (the plugin requires `^3.325.1`). Older versions lack inline template
  support; eligible emails then fail with an error that asks you to update the SDK.
- The IAM user also needs `ses:SendBulkEmail`. Without it SES answers `AccessDeniedException`, and the recipients
  are recorded as `rejected`.
- The outbox tables `ses_bulk_contents` and `ses_bulk_deliveries` (with your Mautic table prefix). A new plugin
  installation creates them. An existing installation gets them from the plugin migration when
  `bin/console mautic:plugins:reload` (or **Install/Update Plugins**) runs after the plugin version increases, or
  immediately with:

  ```bash
  php bin/console mautic:ses:bulk install
  ```

  Without the tables, eligible emails fail with
  `SES bulk tables are missing. Run bin/console mautic:ses:bulk install before enabling bulk=auto.`
- An SES configuration set with an event destination that publishes `Send`, `Delivery`, `Bounce`, `Complaint`,
  `Reject` and `Rendering Failure` events to the SNS topic from [SNS Callback Configuration](#sns-callback-configuration).
  Apply it as the default configuration set of the sending identity, or add the custom header
  `X-SES-CONFIGURATION-SET` with its name to the email. The plugin tags every delivery it records with
  `mautic_delivery_id`, and these events are the only way an unknown outcome becomes known. `Rendering Failure` is
  also the only report of a template that SES could not render.

### When raw sending is used instead

The plugin decides before anything is submitted. Bulk sending needs Mautic's recipient metadata: every recipient must
carry a tracking hash and an email ID, as the recipients of segment emails do. Emails without it are always sent raw.
For the others, the plugin checks the first recipient. If that recipient cannot use a shared template, the whole
email takes the raw path of `bulk=off` unchanged (raw MIME per recipient, micro-batches, inline retries after 1, 2
and 4 seconds) and nothing is written to the outbox. The transport logs
`SES raw sending: message is not eligible for shared templates.` with the reason at `info` level, which Mautic's
production log configuration does not write to `var/logs`.

| Reason                        | Cause                                                                                                                                           |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `attachments`                 | The email has attachments.                                                                                                                      |
| `cc_or_bcc`                   | The email has CC or BCC recipients.                                                                                                             |
| `custom_mime`                 | The email has an explicit MIME body, for example a signed or encrypted one.                                                                     |
| `charset`                     | The HTML or text part is not UTF-8.                                                                                                             |
| `stream_body`, `empty_body`   | A body part is a stream, or the email has neither HTML nor text.                                                                                |
| `literal_template_delimiters` | `{{` or `}}` appears in the subject, a body part or a resolved token value.                                                                     |
| `unsupported_token`           | A token key is not of the form `{…}`, or a token value is an array or object.                                                                   |
| `case_colliding_tokens`       | Two token keys differ only in case.                                                                                                             |
| `unsupported_header`          | A header other than `X-*`, `List-*`, `Precedence`, `Feedback-ID`, `Auto-Submitted` and the address, subject, date, message ID and MIME headers. |
| `sender_differs_from_from`    | A `Sender` header that differs from `From`. Mautic 7 sets `Sender` to the `From` address, which is supported.                                   |
| `header_count`                | More than 15 of the supported headers.                                                                                                          |

When the first recipient passes and a later one does not, only that recipient is sent raw. The typical reasons are
per recipient: `replacement_data_size` (replacement data over 262,144 bytes), `request_size` (a request with this
recipient alone would exceed 1,000,000 bytes), `header_size_or_folding` (a header name over 126 bytes, or a value
over 870 bytes or with a line break) and `invalid_utf8`. The token-related reasons above
(`literal_template_delimiters` in a token value, `unsupported_token`, `case_colliding_tokens`) can also apply. Such
a recipient gets the same raw MIME message as on the raw path, submitted as its own `SendEmail` request through the
outbox, so `status` shows it with mode `raw` and the reason, and it gets the outbox's retry handling.

### The `mautic:ses:bulk` command

```bash
php bin/console mautic:ses:bulk install
php bin/console mautic:ses:bulk status [--email-id=ID] [--json]
php bin/console mautic:ses:bulk retry [--limit=N]
php bin/console mautic:ses:bulk sync-stats [--limit=N]
```

| Action       | What it does                                                                                                                                                                                                                                                                                       |
|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `install`    | Creates the outbox tables that do not exist yet. Safe to run again.                                                                                                                                                                                                                                |
| `status`     | Recipients per mode (`bulk` or `raw`), submission state, SES event and reason, with their attempts, plus the requests and estimated request bytes per mode. `--email-id` limits it to one Mautic email; `--json` prints the same data as JSON. Only recipients recorded in the outbox are counted. |
| `retry`      | Turns stale claims into `unknown`, resubmits due `pending` and `retry` rows, then reconciles statistics like `sync-stats`. It reads `mailer_dsn`, requires `bulk=auto` and handles the rows of every email sent with the same region and access key.                                               |
| `sync-stats` | Sets `is_failed` on Mautic's email statistics for recipients that are `rejected` or whose SES event is `bounced`, `rejected` or `rendering_failed`. It adds no Do Not Contact entries.                                                                                                             |

`--limit` (1 to 10000, default 1000) caps the recipients that one run resubmits and reconciles. After switching back
to `bulk=off`, `retry` refuses to run and rows left in `retry` wait until `bulk=auto` is configured again;
`sync-stats` keeps working.

Run `retry` from cron every 5 minutes, as the same user as Mautic's other cron jobs and workers (the token bucket file
is in Mautic's cache directory):

```text
*/5 * * * * php /path/to/mautic/bin/console mautic:ses:bulk retry
```

### Outcomes and retries

| State      | Meaning                                                                                                                                                                                                                                                                                                                                               |
|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pending`  | Recorded, not submitted yet. The sending process submits it; `retry` submits rows that a stopped process left behind.                                                                                                                                                                                                                                 |
| `sending`  | Claimed by a process; the request may be in flight.                                                                                                                                                                                                                                                                                                   |
| `accepted` | SES accepted the recipient and returned a message ID.                                                                                                                                                                                                                                                                                                 |
| `retry`    | A temporary failure: `ACCOUNT_THROTTLED`, `ACCOUNT_DAILY_QUOTA_EXCEEDED`, `TRANSIENT_FAILURE` or `FAILED` for the recipient, a throttling error for the whole request, or a local error before submission (`local_preflight_failure`).                                                                                                                |
| `rejected` | A permanent failure (for example `MESSAGE_REJECTED`, `MAIL_FROM_DOMAIN_NOT_VERIFIED` or `AccessDeniedException`), an SDK validation error (`sdk_validation`) or exhausted retries (`retry_exhausted:<status>`).                                                                                                                                       |
| `unknown`  | SES may or may not have accepted it: a timeout, broken connection, HTTP 5xx or other error (`ambiguous_request_failure`), a result list that does not match the request (`invalid_result_count`), an unrecognized status (`unrecognized_result`), a raw send without message ID (`missing_result`), or an interrupted process (`worker_interrupted`). |

- `accepted` is not delivered. The `SES event` column shows `sent`, `delivered`, `bounced`, `complained`,
  `rendering_failed` or `rejected` once the SNS events arrive.
- `unknown` is never retried automatically: SES offers no idempotency key, so a resubmission could send the email
  twice. An SES event for the delivery later marks it `accepted` with that event.
- Rows in `retry` are resubmitted only by `mautic:ses:bulk retry`. There are up to 3 retries, which become due 60 s,
  120 s and 240 s after the failed attempt; with the cron above, a retry runs up to 5 minutes after it becomes due.
  If the fourth attempt also ends in `retry`, the row becomes `rejected` with reason `retry_exhausted:<status>`.
- A row still `sending` 10 minutes after its claim becomes `unknown` (`worker_interrupted`) when the next bulk send
  or `retry` run starts.
- Every submission, first attempt or retry, is charged against the shared token bucket per recipient.
- `sync-stats` and `retry` reconcile failed recipients into the `is_failed` flag of Mautic's email statistics without
  creating Do Not Contact entries. Mautic's own sent count includes every recipient handed to the transport. Bounce
  and complaint notifications still add Do Not Contact entries through the SNS callback, as before.

### Offline benchmark

Measured locally on 2026-09-26 against the fake SES endpoint, not in production: Mautic 7.2.1, a real 164 KB
newsletter, 1,004 contacts, one sending process. SES processing, network latency to AWS and real throttling are not
part of these numbers.

|                                    | `bulk=auto` | `bulk=off` |
|------------------------------------|-------------|------------|
| SES requests                       | 21          | 1,004      |
| Request bodies uploaded            | 15.1 MB     | 320.9 MB   |
| User CPU time                      | 5.4 s       | 8.5 s      |
| Peak memory of the sending process | 136 MB      | 631 MB     |

With `ratelimit=80` and 100 ms of added latency per request (404 contacts), one process reached 57 recipients/s with
`bulk=auto` and 27 recipients/s with `bulk=off`.

### Testing

- [docs/SES_E2E_TESTING.md](docs/SES_E2E_TESTING.md): offline, SES sandbox and production canary tests, with what
  each of them proves.
- [Tests/E2E/offline/README.md](Tests/E2E/offline/README.md): the scripted offline harness, including queued sending
  with parallel workers and the benchmark script.

---

## Debugging

- To troubleshoot email sending or SNS callback issues, check Mautic’s logs:

  ```
  /path/to/mautic/var/logs
  ```

- You can also monitor SES and SNS performance in **Amazon CloudWatch**.

---

## Contributions & Feedback

This is my first Mautic plugin, so I’m open to any feedback or improvements.  
Feel free to open an issue or submit a pull request if you find a bug or have a feature request!

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes. Version 1.0.31 maintains compatibility with PHP 8.1 for Mautic 6 users, while supporting Mautic 7 (which requires PHP 8.2).
