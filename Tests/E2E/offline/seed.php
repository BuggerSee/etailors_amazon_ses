<?php

declare(strict_types=1);

/*
 * Seed a local Mautic with an e2e segment and newsletter through Mautic's own models (no HTTP or API credentials needed).
 *
 * Usage: [STATE_FILE=...] [SEED_ADDRESSES=a@x,b@y] [SEED_FROM=...] [SEED_HTML_FILE=...] [SEED_NAME=...] [SEED_SUBJECT=...]
 *        php -d memory_limit=1G seed.php <mautic-root> [count] [domain]
 *
 * Creates <count> ordinary contacts plus transient@, throttled@, rejected@ and flaky@<stamp>.<domain>, a segment holding
 * them and a published segment email, then writes the ids to STATE_FILE (default: <system temp dir>/ses-e2e-state.json).
 * SEED_ADDRESSES (comma-separated) replaces the generated contacts and ignores count and domain: a contact that already
 * exists for an address is reused, without its email do-not-contact entries, the others are created. The segment and the
 * email are new on every run, so every seeded contact is pending. SEED_FROM sets the email's From address
 * (default: sender@example.test); a live run needs an identity SES has verified.
 */

use Mautic\EmailBundle\Entity\Email;
use Mautic\LeadBundle\Entity\Lead;
use Mautic\LeadBundle\Entity\LeadList;

$root = rtrim($argv[1] ?? '', '/');
if ('' === $root || !is_file($root.'/docroot/app/config/bootstrap.php')) {
    fwrite(STDERR, "usage: seed.php <mautic-root> [count] [domain]\n");
    exit(2);
}
$count = (int) ($argv[2] ?? 100);
$domain = $argv[3] ?? 'example.test';
$stamp = date('YmdHis');

require $root.'/docroot/app/config/bootstrap.php';
$kernel = new AppKernel($_SERVER['APP_ENV'], (bool) $_SERVER['APP_DEBUG']);
$kernel->boot();
$container = $kernel->getContainer();
$leadModel = $container->get('mautic.lead.model.lead');
$listModel = $container->get('mautic.lead.model.list');
$emailModel = $container->get('mautic.email.model.email');
$dncModel = $container->get('mautic.lead.model.dnc');

// 1. Contacts: the SEED_ADDRESSES, or N ordinary recipients plus the fake-SES failure-injection local parts.
$emails = [];
$given = (string) getenv('SEED_ADDRESSES');
if ('' !== $given) {
    foreach (array_filter(array_map('trim', explode(',', $given)), 'strlen') as $address) {
        if (false === filter_var($address, FILTER_VALIDATE_EMAIL)) {
            fwrite(STDERR, "SEED_ADDRESSES: not an email address: $address\n");
            exit(2);
        }
        $emails[strtolower($address)] ??= $address;
    }
    $emails = array_values($emails);
    if ([] === $emails) {
        fwrite(STDERR, "SEED_ADDRESSES holds no address\n");
        exit(2);
    }
} else {
    for ($i = 1; $i <= $count; ++$i) {
        $emails[] = sprintf('success%03d.%s@%s', $i, $stamp, $domain);
    }
    // The fake SES server matches these local parts exactly, so the run stamp goes into the domain.
    foreach (['transient', 'throttled', 'rejected', 'flaky'] as $local) {
        $emails[] = sprintf('%s@%s.%s', $local, $stamp, $domain);
    }
}
$leads = [];
$created = [];
foreach ($emails as $address) {
    // Generated addresses carry the run stamp and are always new; given addresses keep their contact across runs.
    $existing = '' !== $given ? $leadModel->getRepository()->getLeadByEmail($address) : null;
    if (null !== $existing) {
        $lead = $leadModel->getEntity((int) $existing['id']);
        // Mautic skips contacts that are do-not-contact for email, such as bounce@ and complaint@ after an earlier live run.
        while ($dncModel->removeDncForContact($lead->getId(), 'email')) {
            printf("removed an email do-not-contact entry of %s\n", $address);
        }
    } else {
        $lead = new Lead();
        $lead->setEmail($address);
        $lead->setFirstname('E2E');
        $lead->setLastname(strstr($address, '@', true));
        $created[] = $lead;
    }
    $leads[] = $lead;
}
if ([] !== $created) {
    $leadModel->saveEntities($created);
}
$contactIds = array_map(static fn (Lead $lead): int => (int) $lead->getId(), $leads);
printf("created %d contacts, reused %d\n", count($created), count($leads) - count($created));

// 2. Segment with manual membership, so the run is deterministic.
$list = new LeadList();
$list->setName('SES bulk e2e '.$stamp);
$list->setPublicName('SES bulk e2e '.$stamp);
$list->setAlias('ses-bulk-e2e-'.$stamp);
$list->setIsPublished(true);
$list->setFilters([]);
$listModel->saveEntity($list);
foreach ($leads as $lead) {
    $listModel->addLead($lead, $list, true);
}
printf("segment %d with %d contacts\n", $list->getId(), count($leads));

// 3. Newsletter: shared content plus the three footer tokens found in the user's real newsletter.
// Mautic 7 only adds List-Unsubscribe when the body contains {unsubscribe_url} (or {unsubscribe_text} with a configured
// unsubscribe_text containing |URL|; the default is null), so the fixture also carries an explicit unsubscribe link.
$html = <<<HTML
<!DOCTYPE html>
<html><body>
<h1>Offline SES bulk e2e</h1>
<p>Shared article text that is identical for every recipient. <a href="https://example.test/article?utm_source=e2e&amp;utm_campaign={$stamp}">Read the article</a></p>
<p>Second shared paragraph with a product link: <a href="https://example.test/product/42?tag=affiliate-21">Product 42</a></p>
<p>You receive this newsletter as {contactfield=email}.</p>
<p>{webview_text}</p>
<p>{unsubscribe_text}</p>
<p><a href="{unsubscribe_url}">Unsubscribe</a></p>
</body></html>
HTML;
// SEED_HTML_FILE lets a run use a real newsletter (for example the compiled MJML) instead of the small fixture.
if ($htmlFile = getenv('SEED_HTML_FILE')) {
    $html = file_get_contents($htmlFile);
    if (false === $html) {
        fwrite(STDERR, "cannot read SEED_HTML_FILE $htmlFile\n");
        exit(2);
    }
}
$plainText = getenv('SEED_HTML_FILE')
    ? trim(preg_replace("/\n{3,}/", "\n\n", strip_tags(preg_replace('/<(style|script)\b[^>]*>.*?<\/\1>/is', '', $html))))
    : "Offline SES bulk e2e\n\nShared article text that is identical for every recipient.\n\nYou receive this newsletter as {contactfield=email}.\n\n{webview_text}\n\n{unsubscribe_text}\n";
$email = new Email();
$email->setName((getenv('SEED_NAME') ?: 'SES bulk e2e newsletter').' '.$stamp);
$email->setSubject((getenv('SEED_SUBJECT') ?: 'Offline SES bulk e2e').' '.$stamp);
$email->setEmailType('list');
$email->addList($list);
$email->setTemplate('blank');
$email->setCustomHtml($html);
$email->setPlainText($plainText);
$email->setIsPublished(true);
// Broadcasts are only picked up when publish_up is set (the UI's send dialog does this).
$email->setPublishUp(new \DateTime('-1 minute', new \DateTimeZone('UTC')));
// Mautic 7 excludes contacts whose segment membership is not older than publish_up unless the email keeps sending to new members.
if (method_exists($email, 'setContinueSending')) {
    $email->setContinueSending(true);
}
$email->setFromAddress(getenv('SEED_FROM') ?: 'sender@example.test');
$email->setFromName('E2E Sender');
try {
    $emailModel->saveEntity($email);
} catch (\Throwable $e) {
    // Post-save listeners can throw outside a web request; the entity is already persisted at that point.
    if (!$email->getId()) {
        throw $e;
    }
    fwrite(STDERR, sprintf("warning: post-save listener threw after the email was stored: %s: %s\n", get_class($e), $e->getMessage()));
}
printf("email %d\n", $email->getId());

$state = ['stamp' => $stamp, 'segment_id' => $list->getId(), 'email_id' => $email->getId(), 'contact_ids' => $contactIds, 'emails' => $emails];
$stateFile = getenv('STATE_FILE') ?: sys_get_temp_dir().'/ses-e2e-state.json';
file_put_contents($stateFile, json_encode($state, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
echo "state written to $stateFile\n";
