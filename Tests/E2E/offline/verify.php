<?php

declare(strict_types=1);

/*
 * Verify an offline SES bulk e2e run: cross-check the fake SES request log, the plugin's outbox
 * tables and Mautic's email statistics for every seeded recipient.
 *
 * Usage: php verify.php <mautic-root> <state.json> <fake-ses-log.jsonl> [--after-retry] [--after-sync]
 *   no flag        right after the send: transient@, throttled@ and flaky@ wait in retry, rejected@ is rejected
 *   --after-retry  after retry runs: flaky@ is accepted, transient@ and throttled@ are still retry while fewer
 *                  than 4 attempts are logged, and rejected with reason retry_exhausted:<status> at the 4th
 *   --after-sync   after sync-stats: email_stats.is_failed is set for exactly the rejected outbox rows
 * Exit code 0 when every check passes, 1 when a check fails, 2 on bad arguments.
 */

$root = rtrim($argv[1] ?? '', '/');
$stateFile = $argv[2] ?? '';
$logFile = $argv[3] ?? '';
$flags = array_slice($argv, 4);
if (!is_file($root.'/config/local.php') || !is_file($stateFile) || !is_file($logFile) || [] !== array_diff($flags, ['--after-retry', '--after-sync'])) {
    fwrite(STDERR, "usage: verify.php <mautic-root> <state.json> <fake-ses-log.jsonl> [--after-retry] [--after-sync]\n");
    exit(2);
}
$afterRetry = in_array('--after-retry', $flags, true);
$afterSync = in_array('--after-sync', $flags, true);

$state = json_decode(file_get_contents($stateFile), true, 512, JSON_THROW_ON_ERROR);
$emailId = (int) $state['email_id'];
$seeded = array_fill_keys(array_map('strtolower', $state['emails']), true);
$contactIds = array_map('intval', $state['contact_ids']);

require $root.'/config/local.php';
$pdo = new PDO(sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $parameters['db_host'], ($parameters['db_port'] ?? null) ?: 3306, $parameters['db_name']), $parameters['db_user'], $parameters['db_password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$prefix = $parameters['db_table_prefix'] ?? '';

$failures = 0;
$check = static function (bool $ok, string $label, string $detail = '') use (&$failures): void {
    if (!$ok) {
        ++$failures;
    }
    printf("%s %s%s\n", $ok ? 'PASS' : 'FAIL', $label, '' !== $detail ? ' — '.$detail : '');
};
$recipient = static fn (string $to): string => strtolower(trim(preg_match('/<([^>]+)>/', $to, $m) ? $m[1] : $to));

// ---- fake SES request log -------------------------------------------------------------------
$bulkRequests = [];
$rawRequests = [];
$accountCalls = 0;
foreach (file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    $entry = json_decode($line, true);
    if (!is_array($entry)) {
        continue;
    }
    if (str_ends_with((string) $entry['path'], '/outbound-bulk-emails')) {
        $bulkRequests[] = $entry;
    } elseif (str_ends_with((string) $entry['path'], '/outbound-emails')) {
        $rawRequests[] = $entry;
    } elseif (str_ends_with((string) $entry['path'], '/account')) {
        ++$accountCalls;
    }
}
// The fake server keeps one log across runs: keep only the requests that belong to this email.
$bulkRequests = array_values(array_filter($bulkRequests, static function (array $req) use ($emailId): bool {
    $tags = array_column($req['request']['BulkEmailEntries'][0]['ReplacementTags'] ?? [], 'Value', 'Name');
    return ($tags['X-EMAIL-ID'] ?? '') === (string) $emailId;
}));
$rawRequests = array_values(array_filter($rawRequests, static function (array $req) use ($emailId): bool {
    $tags = array_column($req['request']['EmailTags'] ?? [], 'Value', 'Name');
    return ($tags['X-EMAIL-ID'] ?? '') === (string) $emailId;
}));
printf("log: %d bulk requests, %d raw requests for email %d, %d account calls\n", count($bulkRequests), count($rawRequests), $emailId, $accountCalls);

// ---- outbox ------------------------------------------------------------------------------------
$deliveries = $pdo->query(sprintf(
    "SELECT d.id, d.tracking_hash, d.state, d.event, d.reason, d.message_id, d.attempts, d.entry, c.operation FROM %sses_bulk_deliveries d JOIN %sses_bulk_contents c ON c.id = d.content_id WHERE d.email_id = %d",
    $prefix, $prefix, $emailId
))->fetchAll(PDO::FETCH_ASSOC);
$byId = array_column($deliveries, null, 'id');
$states = array_count_values(array_column($deliveries, 'state'));
$ops = array_count_values(array_column($deliveries, 'operation'));
printf("outbox: %d deliveries, states=%s, operations=%s\n", count($deliveries), json_encode($states), json_encode($ops));
$check(count($deliveries) === count($seeded), 'one outbox row per seeded recipient', sprintf('%d rows vs %d seeded', count($deliveries), count($seeded)));
$check(($ops['bulk'] ?? 0) === count($deliveries), 'every recipient went through the shared-template path', json_encode($ops));

// ---- bulk entries versus recipients ----------------------------------------------------------
// Every logged entry is one submission: a recipient's first comes from the send, later ones from retry runs.
$logged = [];
foreach ($bulkRequests as $req) {
    foreach ($req['request']['BulkEmailEntries'] ?? [] as $entry) {
        $address = $recipient((string) ($entry['Destination']['ToAddresses'][0] ?? ''));
        $logged[$address] = ($logged[$address] ?? 0) + 1;
    }
}
$submitted = [];
$lastStatus = [];
$templates = [];
$initialSizes = [];
$retrySizes = [];
$entriesSeen = 0;
$bulkBytes = 0;
// The fake server injects failures by exact local part; flaky@ fails only its first submission.
$expectedStatus = static fn (string $local, int $attempt): string => match ($local) {
    'transient' => 'TRANSIENT_FAILURE',
    'throttled' => 'ACCOUNT_THROTTLED',
    'rejected' => 'MESSAGE_REJECTED',
    'flaky' => 1 === $attempt ? 'TRANSIENT_FAILURE' : 'SUCCESS',
    default => 'SUCCESS',
};
// DeliveryStore claims a row at most 4 times; a retryable failure on the 4th attempt rejects it as retry_exhausted.
$maxAttempts = 4;
// [outbox state, outbox reason or null when the reason is not checked] at a recipient's latest submission.
$expectedOutcome = static fn (string $local, int $attempt): array => match ($local) {
    'transient', 'throttled' => $afterRetry && $attempt >= $maxAttempts ? ['rejected', 'retry_exhausted:'.$expectedStatus($local, $attempt)] : ['retry', null],
    'flaky' => [$afterRetry ? 'accepted' : 'retry', null],
    'rejected' => ['rejected', null],
    default => ['accepted', null],
};
foreach ($bulkRequests as $i => $req) {
    $body = $req['request'] ?? null;
    $resp = $req['response'] ?? null;
    if (!is_array($body) || !is_array($resp)) {
        $check(false, "bulk request $i has decoded request/response bodies");
        continue;
    }
    $bulkBytes += strlen(json_encode($body));
    $template = $body['DefaultContent']['Template']['TemplateContent'] ?? null;
    $check(is_array($template) && isset($template['Html'], $template['Subject']), "bulk request $i carries an inline template");
    $templates[hash('sha256', json_encode($template))] = true;
    $entries = $body['BulkEmailEntries'] ?? [];
    $results = $resp['BulkEmailEntryResults'] ?? [];
    $check(count($entries) <= 50 && count($entries) === count($results), "bulk request $i has <=50 entries and one result per entry", count($entries).' entries');
    $firstSubmissions = 0;
    foreach ($entries as $n => $entry) {
        ++$entriesSeen;
        $address = $recipient((string) ($entry['Destination']['ToAddresses'][0] ?? ''));
        $local = strstr($address, '@', true) ?: $address;
        $attempt = $submitted[$address] = ($submitted[$address] ?? 0) + 1;
        $firstSubmissions += 1 === $attempt ? 1 : 0;
        $status = (string) ($results[$n]['Status'] ?? '');
        $previous = $lastStatus[$address] ?? null;
        $lastStatus[$address] = $status;
        $data = json_decode((string) ($entry['ReplacementEmailContent']['ReplacementTemplate']['ReplacementTemplateData'] ?? ''), true);
        $tags = array_column($entry['ReplacementTags'] ?? [], 'Value', 'Name');
        $headers = array_column($entry['ReplacementHeaders'] ?? [], 'Value', 'Name');
        $deliveryId = $tags['mautic_delivery_id'] ?? '';
        $row = $byId[$deliveryId] ?? null;
        $ok = isset($seeded[$address]) && is_array($data) && null !== $row && ($tags['X-EMAIL-ID'] ?? '') === (string) $emailId;
        if (!$ok) {
            $check(false, "entry $i/$n ($address) is a seeded recipient with data, delivery id and X-EMAIL-ID tag", json_encode(['data' => is_array($data), 'row' => null !== $row, 'tags' => $tags]));
            continue;
        }
        $render = static fn (string $part): string => preg_replace_callback('/\{\{([a-zA-Z0-9_]+)\}\}/', static fn (array $mm): string => (string) ($data[$mm[1]] ?? "<<MISSING {$mm[1]}>>"), $part);
        $html = $render((string) $template['Html']);
        $text = $render((string) ($template['Text'] ?? ''));
        $subject = $render((string) $template['Subject']);
        $hash = $row['tracking_hash'];
        $problems = [];
        if (!str_contains(strtolower($html), $address)) {
            $problems[] = 'recipient address missing from rendered HTML';
        }
        if (!str_contains($html, $hash)) {
            $problems[] = 'tracking hash missing from rendered HTML (pixel/unsubscribe)';
        }
        if (preg_match('/\{(contactfield=|unsubscribe_text|webview_text|tracking_pixel|trackable=|leadfield=)/', $html.$text.$subject)) {
            $problems[] = 'unreplaced Mautic token in rendered output';
        }
        if (str_contains($html.$text.$subject, '{{') || str_contains($html, '<<MISSING')) {
            $problems[] = 'template delimiter or missing variable in rendered output';
        }
        if (!isset($headers['List-Unsubscribe']) || !str_contains($headers['List-Unsubscribe'], $hash)) {
            $problems[] = 'List-Unsubscribe header missing or not recipient-specific';
        }
        $wantStatus = $expectedStatus($local, $attempt);
        if ($status !== $wantStatus) {
            $problems[] = "fake SES returned $status, expected $wantStatus";
        }
        // Only failures the outbox retries may be submitted again; accepted and rejected recipients never are.
        if (null !== $previous && !in_array($previous, ['TRANSIENT_FAILURE', 'ACCOUNT_THROTTLED'], true)) {
            $problems[] = "submitted again after $previous";
        }
        if ('SUCCESS' === $status && ($results[$n]['MessageId'] ?? '') !== $row['message_id']) {
            $problems[] = 'SES MessageId not stored on the outbox row';
        }
        // The outbox row reflects the latest submission, so its state and attempts are judged there.
        if ($attempt === $logged[$address]) {
            [$wantState, $wantReason] = $expectedOutcome($local, $attempt);
            if ($row['state'] !== $wantState) {
                $problems[] = "outbox state {$row['state']}, expected $wantState";
            } elseif (null !== $wantReason && (string) $row['reason'] !== $wantReason) {
                $problems[] = "outbox $wantState with reason {$row['reason']}, expected $wantReason";
            }
            if ((int) $row['attempts'] !== $attempt) {
                $problems[] = "outbox counts {$row['attempts']} attempts, the fake SES log $attempt";
            }
        }
        $check([] === $problems, "entry $i/$n $address (attempt $attempt) renders and reconciles", implode('; ', $problems));
    }
    if ($firstSubmissions > 0) {
        $initialSizes[] = count($entries);
    } else {
        $retrySizes[] = count($entries);
    }
}
$check([] === array_diff_key($seeded, $submitted) && [] === array_diff_key($submitted, $seeded), 'every seeded recipient appears exactly once across the initial bulk entries', sprintf('%d distinct addresses in %d entries (%d resubmissions)', count($submitted), $entriesSeen, $entriesSeen - count($submitted)));
$check(1 === count($templates), 'all bulk requests share one identical inline template', count($templates).' distinct templates');
$check(count($initialSizes) === (int) ceil(count($seeded) / 50), 'initial request count equals ceil(recipients / 50)', count($initialSizes).' requests for '.count($seeded).' recipients; batch sizes '.implode(',', $initialSizes).'; '.count($retrySizes).' retry requests'.([] === $retrySizes ? '' : ' of '.implode(',', $retrySizes)));
printf("bytes: %d bytes of bulk request JSON for %d entries (%.1f KB per entry)\n", $bulkBytes, max(1, $entriesSeen), $bulkBytes / 1024 / max(1, $entriesSeen));

// ---- Mautic statistics -----------------------------------------------------------------------
$stats = $pdo->query(sprintf('SELECT tracking_hash, is_failed, email_address FROM %semail_stats WHERE email_id = %d', $prefix, $emailId))->fetchAll(PDO::FETCH_ASSOC);
$check(count($stats) === count($seeded), 'Mautic recorded one email_stats row per recipient', count($stats).' rows');
$statsByHash = array_column($stats, null, 'tracking_hash');
$missing = 0;
foreach ($deliveries as $row) {
    if (!isset($statsByHash[$row['tracking_hash']])) {
        ++$missing;
    }
}
$check(0 === $missing, 'every outbox row maps to an email_stats row by tracking hash', "$missing unmatched");
if ($afterSync) {
    $failed = array_sum(array_map(static fn (array $s): int => (int) $s['is_failed'], $stats));
    $rejected = $states['rejected'] ?? 0;
    $check($failed === $rejected, 'sync-stats flagged exactly the rejected recipients as failed', "$failed failed vs $rejected rejected");
}
$dnc = [] === $contactIds ? 0 : (int) $pdo->query(sprintf('SELECT COUNT(*) FROM %slead_donotcontact WHERE lead_id IN (%s)', $prefix, implode(',', $contactIds)))->fetchColumn();
$check(0 === $dnc, 'no do-not-contact entries were created by transport failures', "$dnc rows for the seeded contacts");

printf("\n%s: %d failing check(s)\n", 0 === $failures ? 'ALL CHECKS PASSED' : 'CHECKS FAILED', $failures);
exit(0 === $failures ? 0 : 1);
