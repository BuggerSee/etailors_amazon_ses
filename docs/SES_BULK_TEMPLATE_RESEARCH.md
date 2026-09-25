# SES bulk templates and Mautic: feasibility research

Researched 2026-09-25. Plugin baseline: upstream 1.0.41 (`46b8ddb`). Mautic current-source inspection: 6.x commit `f4bec488e1e3424e4ea6918f57dcb27df0d88ef7` and 7.x commit `e16aca5eb9e00adcf97419e0a32d6cc5989e9f21`. Historical comparison: Mautic 4.4.13. These are explicitly identified branch snapshots, not a claim that every released patch version has identical behavior. This is source/API research, not a completed implementation or a live SES compatibility test.

## Finding

**The historical custom-header blocker has been removed by AWS. The plugin has not implemented a replacement bulk-template path.** Mautic's personalization is a compatibility problem to solve and test, not evidence that every newsletter is fundamentally impossible to batch.

**For Mautic 6/7 specifically, bulk templates are still unsupported by the inspected e-tailors plugin.** The old AWS fix did not supply Mautic token conversion, recipient-result accounting or queue recovery. The source supports a custom batch adapter in principle, but does not establish a working SES implementation. Do not describe this as a feature that Mautic 6/7 already fixed or that only needs a configuration switch.

For the user's 150k-recipient newsletter already sending satisfactorily at approximately 80 recipients/sec, this is an optional API/CPU/network-efficiency experiment. It cannot increase the recipient quota or improve the theoretical submission minimum of 31 min 15 sec at that rate.

## 1. The original restriction is explicit in Mautic's source

Mautic 4.4.13's AmazonApiTransport explains around lines 303–307 that its custom-header requirements force raw sending, and that simple/template sending should be reconsidered if AWS supports those headers. That is stronger evidence than inferring the reason from today's plugin.

Source: [historical AmazonApiTransport](https://github.com/mautic/mautic/blob/4.4.13/app/bundles/EmailBundle/Swiftmailer/Transport/AmazonApiTransport.php#L303).

The e-tailors plugin's initial commit had an alternate branch referencing template-building methods, but the inspected class did not supply those methods or enable the template property. The alternate sendBulkEmail branch was removed in commit `ede539f` on 2024-03-08. This history is not proof of a previously complete, working bulk implementation or a documented rejection of every modern template approach.

Sources: [initial plugin transport](https://github.com/pm-pmaas/etailors_amazon_ses/blob/6f03d12/Mailer/Transport/AmazonSesTransport.php), [removal commit](https://github.com/pm-pmaas/etailors_amazon_ses/commit/ede539f).

## 2. What AWS changed

| Date | Change | Relevance |
| --- | --- | --- |
| 2024-03-08 | Custom headers in SES v2 SendEmail and SendBulkEmail. | Removes the old requirement to use raw MIME just to carry unsubscribe and proprietary headers. |
| 2024-11-04 | Inline template content in SendEmail and SendBulkEmail. | A plugin can supply template content per request without creating/deleting stored SES templates for every campaign variant. |
| 2025-04-04 | Attachments through structured SES v2 sending APIs. | Attachments/inline images no longer categorically force raw MIME; bulk template attachments are common to all entries in that request. |

Sources: [headers announcement](https://aws.amazon.com/about-aws/whats-new/2024/03/amazon-ses-headers-sending-email/), [inline templates announcement](https://aws.amazon.com/about-aws/whats-new/2024/11/amazon-ses-inline-template-support-send-email-apis/), [attachments announcement](https://aws.amazon.com/about-aws/whats-new/2025/04/amazon-ses-attachments-sending-apis/), [attachment API guide](https://docs.aws.amazon.com/ses/latest/dg/attachments.html).

Current BulkEmailEntry has ReplacementTemplateData, ReplacementHeaders, and ReplacementTags. Header overrides are per destination, so the adapter can supply each recipient's already-resolved List-Unsubscribe and attribution fields. Headers supplied via the template act as defaults. [BulkEmailEntry reference](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_BulkEmailEntry.html)

This does not permit arbitrary MIME replacement per entry. From/Reply-To and other SES-managed headers cannot be overridden as arbitrary custom headers. Their request-level fields must be respected; partition recipients into compatible groups when those values differ. [Header restrictions](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html)

## 3. What Mautic actually provides

The inspected current MailHelper supports tokenized transports and collects recipient metadata including resolved tokens, contact/email IDs, source and tracking hash. It groups queued contacts by sender and supplies those groups to the transport. MauticMessage exposes that metadata.

This means a compatible adapter need not ask SES to run Mautic or access its contact database. Mautic can continue computing recipient-specific values, including tracking and unsubscribe URLs, before the transport submits them.

However, MailHelper::searchReplaceTokens() uses case-insensitive replacement across HTML, subject, unstructured headers and text; changed text is stripped of HTML tags. The plugin also sorts tokens and sets recipient tracking state before raw serialization. A naive replacement of `{mautic_token}` with `{{ses_token}}` does not establish equivalent behavior for overlapping/nested replacements, URL encoding, text/HTML contexts or extensions.

Mautic's helper explicitly disables tokenized batching when S/MIME signing is enabled. Exact signed MIME and arbitrary MIME transformations cannot be reproduced by allowing SES to reconstruct the message.

Sources: [MailHelper at the inspected revision](https://github.com/mautic/mautic/blob/e16aca5eb9e00adcf97419e0a32d6cc5989e9f21/app/bundles/EmailBundle/Helper/MailHelper.php), [MauticMessage](https://github.com/mautic/mautic/blob/e16aca5eb9e00adcf97419e0a32d6cc5989e9f21/app/bundles/EmailBundle/Mailer/Message/MauticMessage.php).

The e-tailors transport at 1.0.41 still sends raw Content per recipient through SendEmail. Its enableTemplate property is not wired to a working bulk-template implementation. Updating AWS's SDK alone does not activate bulk sends. [Current plugin transport](https://github.com/pm-pmaas/etailors_amazon_ses/blob/46b8ddb/Mailer/Transport/AmazonSesTransport.php)

### Why Mautic 6 and 7 still do not provide working SES bulk templates here

**1. Queue batching, parallel requests and provider bulk templating are separate mechanisms.**

In 6.x MailHelper checks TokenTransportInterface around line 267; queue(), flushQueue() and buildMetadata() retain recipient-specific data. The 7.x helper likewise supports that interface. These hooks let a plugin implement batch sending, but the e-tailors plugin currently expands the metadata into many SendEmail commands with Content.Raw. Its worker/micro-batch improvements make those separate requests concurrent; they do not use SES's template engine.

Evidence: [Mautic 6 batching hook](https://github.com/mautic/mautic/blob/f4bec488e1e3424e4ea6918f57dcb27df0d88ef7/app/bundles/EmailBundle/Helper/MailHelper.php#L267), [Mautic 7 batching hook](https://github.com/mautic/mautic/blob/e16aca5eb9e00adcf97419e0a32d6cc5989e9f21/app/bundles/EmailBundle/Helper/MailHelper.php#L276), [plugin command creation](https://github.com/pm-pmaas/etailors_amazon_ses/blob/46b8ddb/Mailer/Transport/AmazonSesTransport.php#L166).

**2. SendBulkEmail accepts template data, not a list of already-built raw MIME messages.**

The existing plugin calls Mautic's replacement function per recipient, then serializes MIME with toString(). There is no equivalent Raw field in BulkEmailEntry. Swapping the API method would therefore be invalid. The adapter must preserve the original rendering while constructing a different payload model; AWS's newer headers do not perform this conversion.

Evidence: [current conversion loop](https://github.com/pm-pmaas/etailors_amazon_ses/blob/46b8ddb/Mailer/Transport/AmazonSesTransport.php#L305), [SES BulkEmailEntry](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_BulkEmailEntry.html).

**3. Mautic 6/7 personalization is not interchangeable with simple SES substitution.**

Both inspected helpers replace tokens case-insensitively across HTML, subject, text and unstructured headers. The send-event system also generates contact-specific values. In the 7.x TokenSubscriber, dynamic content is selected using contact filters, then dispatched through further display/token processing before being added as token content. None of these rules executes in SES just because a field is renamed to {{token}}. Header values need local resolution, and HTML/text can require different values. Sender/reply-to and attachment variations need compatible grouping. Mautic 7 explicitly disables tokenized mode for S/MIME.

This establishes necessary integration work, not an absolute impossibility: dynamic content can sometimes be passed as an already-resolved fragment, while other cases can use raw fallback. Which strategy covers the user's newsletter remains untested.

Evidence: [Mautic 6 replacement function](https://github.com/mautic/mautic/blob/f4bec488e1e3424e4ea6918f57dcb27df0d88ef7/app/bundles/EmailBundle/Helper/MailHelper.php#L628), [Mautic 7 dynamic token processing](https://github.com/mautic/mautic/blob/e16aca5eb9e00adcf97419e0a32d6cc5989e9f21/app/bundles/EmailBundle/EventListener/TokenSubscriber.php#L73).

**4. Partial failures do not fit the ordinary mailer success/exception contract.**

The 6.x MailHelper send() exception path around lines 393–410 marks the tokenized message's recipient set as failed. The equivalent 7.x path does the same around lines 409–425. SES can instead return success for some bulk entries and failure for others. Throwing one transport exception is insufficient to communicate that result safely. Mutating only an in-memory recipient list is also insufficient for durable Messenger redelivery, as the plugin's prior duplicate-send fix already documents. A bulk implementation needs recipient outcomes, failed-only retry work, and preserved Mautic statistics.

This failure model also affects today's plugin batches; it is not a newly discovered restriction unique to SendBulkEmail. Bulk mode must not perpetuate it.

Evidence: [Mautic 6 failure handling](https://github.com/mautic/mautic/blob/f4bec488e1e3424e4ea6918f57dcb27df0d88ef7/app/bundles/EmailBundle/Helper/MailHelper.php#L393), [Mautic 7 failure handling](https://github.com/mautic/mautic/blob/e16aca5eb9e00adcf97419e0a32d6cc5989e9f21/app/bundles/EmailBundle/Helper/MailHelper.php#L409), [plugin duplicate-send fix](https://github.com/pm-pmaas/etailors_amazon_ses/commit/6180fb4).

The Mautic team's mailer-refactor discussion explicitly identifies the mismatch between Symfony's one-message interface and marketing batch APIs. It is historical design context, not proof that its proposed replacement architecture was implemented. The default Symfony SES transports inspected in 6.4 and 7.3 construct SendEmailRequest, not SendBulkEmail requests; upgrading Symfony alone does not add the missing plugin adapter.

Sources: [Mautic mailer design discussion](https://github.com/mautic/mautic/issues/12096), [Symfony 6.4 SES transport](https://github.com/symfony/amazon-mailer/blob/6.4/Transport/SesApiAsyncAwsTransport.php), [Symfony 7.3 SES transport](https://github.com/symfony/amazon-mailer/blob/7.3/Transport/SesApiAsyncAwsTransport.php).

**Research boundary:** source/history/API checks confirm the above obstacles. Issue searches did not identify a merged Mautic 6/7 fix that implements this plugin's SES bulk path, nor a definitive maintainer statement that all custom SES bulk adapters are impossible. The two candidate designs below remain hypotheses to validate, not supported features to enable.

## 4. Two possible adapter designs

### A. Shared template plus recipient data

Build one SES template from the common newsletter structure, translate only proven-safe placeholders to generated SES variable names, and pass the Mautic-computed values per recipient. Resolve custom headers locally into ReplacementHeaders; retain Mautic attribution using ReplacementTags and permitted headers. Group by sender, reply-to, configuration set, shared attachments and content compatibility.

Benefit: fewer requests and less repeated HTML upload; potentially less local MIME construction and token substitution.

Challenge: preserving Mautic's exact replacement order, context handling, dynamic content and extension behavior. Inline templates support simple substitutions; stored templates have richer Handlebars capabilities, but neither executes Mautic's dynamic-content engine. Keep Mautic's logic local and use an explicit eligibility test with raw fallback.

### B. Mautic-rendered bodies through a minimal wrapper template

Let Mautic/the existing conversion logic resolve each recipient's subject, HTML, text, links and permitted headers. Submit a minimal SES template whose fields contain placeholders for the finished subject/HTML/text, with each destination providing its already-rendered values.

Conceptual template, not validated implementation:

```json
{
  "Subject": "{{rendered_subject}}",
  "Html": "{{rendered_html}}",
  "Text": "{{rendered_text}}"
}
```

This avoids translating every Mautic token into SES logic. It may save request setup and MIME construction, but it **does not eliminate Mautic rendering or repeated body upload**. SES still constructs the final MIME, so compare semantic output, not byte-for-byte MIME boundaries. Verify HTML insertion/escaping, literal template delimiters, subject/text behavior and headers with the actual SES renderer before calling it compatible.

The wrapper is a feasibility candidate inferred from the replacement-data API, not a tested AWS/Mautic integration. Do not assume a generic Handlebars implementation proves SES's inline behavior.

## 5. Limits that matter to the claimed performance gain

| Constraint | Design consequence |
| --- | --- |
| Up to 50 destinations per bulk call. | 150k recipients could mean about 3,000 calls only if groups can actually fill 50 entries. |
| Documented inline input JSON limit: 1 MB. | Finished-body wrappers can hit the request-size limit well before 50 recipients. Measure serialized UTF-8 JSON, not just HTML size. |
| ReplacementTemplateData maximum string length: 262,144. | Large rendered messages may not fit as replacement data and need raw fallback or another strategy. |
| Template/entry header arrays have documented limits. | Validate all required custom headers and avoid dropping extras to fit bulk mode. |
| Attachments belong to the shared Template. | Different recipient attachments require separate compatible groups or raw sends. |
| Inline template content supports simple substitutions. | Do not migrate Mautic conditionals/custom execution into SES without explicit compatibility work. |
| Per-entry responses and later rendering failures. | Inspect every entry result and ingest Rendering Failure events; request success alone is insufficient. |

For example, 50 finished bodies of 200 KB each would already be about 10 MB before JSON overhead, exceeding the documented inline input limit. Even five such entries approach 1 MB. Thus the earlier 3,000-call figure is a best-case bound, not a realistic universal expectation for personalized body wrappers.

Sources: [template sending limits and rendering failures](https://docs.aws.amazon.com/ses/latest/dg/send-personalized-email-api.html), [replacement data limit](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_ReplacementTemplate.html), [template fields](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_Template.html), [bulk response model](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendBulkEmail.html).

## 6. Proposed decision experiment

1. Record actual Mautic version, installed AWS SDK version, representative rendered message sizes, existing custom headers, attachments and extension hooks. Check SDK model support for every proposed field; the plugin's broad ^3.0 requirement does not prove an installed old SDK knows the newer API fields.
2. Capture a synthetic/anonymized representative newsletter fixture at the same transport boundary as the current raw path, with recipient variations for names, Unicode, HTML/text, URLs, tracking hashes, unsubscribe URLs, dynamic blocks and owner-as-sender.
3. Build an offline eligibility/payload prototype for both designs. Report the proportion of the actual newsletter that can be grouped, real serialized request sizes, raw-fallback reasons, local CPU and memory. Do not send production campaigns as part of this experiment.
4. For a separately authorized SES integration check, compare stored-template previews where useful and controlled seed deliveries for the actual inline path. TestRenderEmailTemplate requires a stored TemplateName and is limited to one request/sec; it is not an inline rendering test endpoint.
5. Verify every selected recipient has correct links/headers/attribution and that exact signed/custom MIME cases fall back. Check body insertion and literal braces explicitly. Exercise partial entry failures, response loss and asynchronous rendering failures.
6. Reuse the shared recipient limiter and durable failed-only recovery design. Do not fall back to raw sending for an ambiguously accepted whole request: that can duplicate sends.
7. At the same 80/s budget, compare accepted throughput, actual requests per 150k recipients, bytes uploaded, CPU time, peak memory and worker count. Ship opt-in only if benefits exceed integration complexity without loss of correctness.

Source for preview restrictions: [TestRenderEmailTemplate API](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_TestRenderEmailTemplate.html).

Decision: **worth a bounded compatibility spike, not yet a promised optimization**. The precise historical blocker was fixed by AWS; implementation, payload limits and Mautic parity remain the plugin's work.
