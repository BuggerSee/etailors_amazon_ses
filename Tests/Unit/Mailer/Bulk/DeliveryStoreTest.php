<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk;

use Doctrine\DBAL\Logging\Middleware;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\Persistence\Mapping\Driver\StaticPHPDriver;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\DeliveryStore;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

class DeliveryStoreTest extends TestCase
{
    public static function manager(array $middlewares = []): EntityManager
    {
        $config = ORMSetup::createConfiguration(true);
        $config->setMetadataDriverImpl(new StaticPHPDriver([dirname(__DIR__, 4).'/Entity']));
        $config->setMiddlewares($middlewares);

        return EntityManager::create(['driver' => 'pdo_sqlite', 'memory' => true], $config);
    }

    public static function delivery(string $id = 'first'): array
    {
        $id = hash('sha256', $id);

        return [
            'id' => $id, 'email_id' => 42, 'tracking_hash' => 'tracking-'.$id,
            'operation' => 'bulk', 'reason' => '',
            'common' => ['FromEmailAddress' => 'sender@example.com', 'DefaultContent' => ['Template' => ['TemplateContent' => ['Subject' => 'News', 'Html' => '<p>Hello {{name}}</p>'], 'TemplateData' => '{}']]],
            'entry' => ['Destination' => ['ToAddresses' => ['recipient@example.com']], 'ReplacementEmailContent' => ['ReplacementTemplate' => ['ReplacementTemplateData' => '{"name":"Reader"}']], 'ReplacementTags' => [['Name' => 'mautic_delivery_id', 'Value' => $id]]],
        ];
    }

    public function testInstallClaimAndReplay(): void
    {
        $em = self::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $store->install();
        $id = $store->enqueue(self::delivery(), 'scope');
        $first = $store->claim($id, 'scope', 'worker-a');
        self::assertNotNull($first);
        self::assertNull($store->claim($id, 'scope', 'worker-b'));
        $store->complete($first, 'accepted', '', 'ses-id');
        $store->enqueue(self::delivery(), 'scope');
        self::assertNull($store->claim($id, 'scope', 'worker-b'));
        self::assertSame('accepted', $store->summary(42)['recipients'][0]['state']);
    }

    public function testSharedContentIsInsertedOncePerStore(): void
    {
        $log = new class() extends AbstractLogger {
            public array $sql = [];

            public function log($level, $message, array $context = []): void
            {
                $this->sql[] = $context['sql'] ?? '';
            }
        };
        $em = self::manager([new Middleware($log)]);
        $db = $em->getConnection();
        $store = new DeliveryStore($em);
        $store->install();
        $store->enqueue(self::delivery('first'), 'scope');
        $store->enqueue(self::delivery('second'), 'scope');
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
        self::assertCount(1, preg_grep('/^INSERT INTO ses_bulk_contents /', $log->sql));
        // Another worker starts without the cache; its insert hits the existing row and is ignored.
        (new DeliveryStore($em))->enqueue(self::delivery('third'), 'scope');
        self::assertCount(2, preg_grep('/^INSERT INTO ses_bulk_contents /', $log->sql));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
        self::assertSame(3, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_deliveries'));
    }

    public function testAcceptedRetryClearsEarlierFailureReason(): void
    {
        $em = self::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $id = $store->enqueue(self::delivery(), 'scope');
        $store->complete($store->claim($id, 'scope', 'worker-a'), 'retry', 'TRANSIENT_FAILURE');
        self::assertSame('TRANSIENT_FAILURE', $store->summary(42)['recipients'][0]['reason']);
        $em->getConnection()->executeStatement('UPDATE ses_bulk_deliveries SET next_attempt = 0');
        $retried = $store->claim($id, 'scope', 'worker-b');
        self::assertNotNull($retried);
        $store->complete($retried, 'accepted', '', 'ses-id');
        $recipients = $store->summary(42)['recipients'];
        self::assertCount(1, $recipients);
        self::assertSame('accepted', $recipients[0]['state']);
        self::assertSame('', $recipients[0]['reason']);
    }

    public function testAcceptedFirstAttemptKeepsRawFallbackReason(): void
    {
        $store = new DeliveryStore(self::manager());
        $store->install();
        $id = $store->enqueue(['operation' => 'raw', 'reason' => 'literal_template_delimiters'] + self::delivery(), 'scope');
        $store->complete($store->claim($id, 'scope', 'worker'), 'accepted', '', 'ses-id');
        $recipients = $store->summary(42)['recipients'];
        self::assertCount(1, $recipients);
        self::assertSame(['raw', 'accepted', 'literal_template_delimiters'], [$recipients[0]['operation'], $recipients[0]['state'], $recipients[0]['reason']]);
    }

    public function testExpiredClaimsAreUnknownNotRetryable(): void
    {
        $em = self::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $id = $store->enqueue(self::delivery(), 'scope');
        $store->claim($id, 'scope', 'dead-worker');
        $em->getConnection()->executeStatement('UPDATE ses_bulk_deliveries SET updated_at = 0');
        self::assertSame(1, $store->expireClaims('scope'));
        self::assertSame([], $store->due('scope', 100));
        self::assertSame('unknown', $store->summary()['recipients'][0]['state']);
    }

    public function testNotificationBeforeResponseAndOutOfOrderEvents(): void
    {
        $store = new DeliveryStore(self::manager());
        $store->install();
        $id = $store->enqueue(self::delivery(), 'scope');
        $row = $store->claim($id, 'scope', 'worker');
        $event = ['mail' => ['messageId' => 'ses-id', 'tags' => ['mautic_delivery_id' => [$id]]]];
        $store->recordEvent($event, 'Rendering Failure');
        $store->complete($row, 'accepted', '', 'ses-id');
        $store->recordEvent($event, 'Send');
        self::assertSame('rendering_failed', $store->summary()['recipients'][0]['event']);
        self::assertSame([], $store->due('scope', 100));
    }

    public function testStatsReconciliationWaitsForStatAndDoesNotAddDnc(): void
    {
        $em = self::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $em->getConnection()->executeStatement('CREATE TABLE email_stats (id INTEGER PRIMARY KEY, email_id INTEGER, tracking_hash VARCHAR(191), is_failed INTEGER)');
        $delivery = self::delivery();
        $id = $store->enqueue($delivery, 'scope');
        $row = $store->claim($id, 'scope', 'worker');
        $store->complete($row, 'rejected', 'INVALID_PARAMETER');
        self::assertSame(['reconciled' => 0, 'without_statistic' => 0], $store->syncFailures());
        $em->getConnection()->insert('email_stats', ['id' => 1, 'email_id' => 42, 'tracking_hash' => $delivery['tracking_hash'], 'is_failed' => 0]);
        self::assertSame(['reconciled' => 1, 'without_statistic' => 0], $store->syncFailures());
        self::assertSame(1, (int) $em->getConnection()->fetchOne('SELECT is_failed FROM email_stats'));
        self::assertSame(['reconciled' => 0, 'without_statistic' => 0], $store->syncFailures());
    }

    public function testRowsWithoutStatisticNeverHoldUpReconciliation(): void
    {
        $em = self::manager();
        $db = $em->getConnection();
        $store = new DeliveryStore($em);
        $store->install();
        $db->executeStatement('CREATE TABLE email_stats (id INTEGER PRIMARY KEY, email_id INTEGER, tracking_hash VARCHAR(191), is_failed INTEGER)');
        foreach (['orphan', 'current'] as $name) {
            $store->complete($store->claim($store->enqueue(self::delivery($name), 'scope'), 'scope', 'worker'), 'rejected', 'MESSAGE_REJECTED');
        }
        // The orphan is older and its statistic is gone, for example because its email was deleted.
        $db->executeStatement('UPDATE ses_bulk_deliveries SET updated_at = ? WHERE id = ?', [time() - 3600, hash('sha256', 'orphan')]);
        $db->insert('email_stats', ['id' => 1, 'email_id' => 42, 'tracking_hash' => 'tracking-'.hash('sha256', 'current'), 'is_failed' => 0]);

        self::assertSame(['reconciled' => 1, 'without_statistic' => 0], $store->syncFailures(1));
        self::assertSame(1, (int) $db->fetchOne('SELECT is_failed FROM email_stats'));
        // Within a day the orphan keeps waiting for its statistic; after that it counts as reconciled.
        $db->executeStatement('UPDATE ses_bulk_deliveries SET updated_at = ? WHERE id = ?', [time() - 86401, hash('sha256', 'orphan')]);
        self::assertSame(['reconciled' => 0, 'without_statistic' => 1], $store->syncFailures(1));
        self::assertSame(['reconciled' => 0, 'without_statistic' => 0], $store->syncFailures(1));
    }

    public function testReleaseDoesNotSpendTheAttempt(): void
    {
        $em = self::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $id = $store->enqueue(self::delivery(), 'scope');
        for ($i = 0; $i < 5; ++$i) {
            $store->release($store->claim($id, 'scope', 'worker'), 'local_preflight_failure', 60);
            $row = $em->getConnection()->fetchAssociative('SELECT state, attempts, reason, next_attempt FROM ses_bulk_deliveries');
            self::assertSame(['retry', 0, 'local_preflight_failure'], [$row['state'], (int) $row['attempts'], $row['reason']]);
            self::assertGreaterThanOrEqual(time() + 59, (int) $row['next_attempt']);
            $em->getConnection()->executeStatement('UPDATE ses_bulk_deliveries SET next_attempt = 0');
        }
        // Accepted on the first real attempt, the release reason does not stay.
        self::assertSame('accepted', $store->complete($store->claim($id, 'scope', 'worker'), 'accepted', '', 'ses-id'));
        self::assertSame(['accepted', '', 1], array_map(static fn ($value) => is_numeric($value) ? (int) $value : $value, array_values($em->getConnection()->fetchAssociative('SELECT state, reason, attempts FROM ses_bulk_deliveries'))));
    }

    public function testFailedMessageLeavesNothingBehind(): void
    {
        $em = self::manager();
        $db = $em->getConnection();
        $store = new DeliveryStore($em);
        $store->install();
        $batches = (static function (): \Generator {
            yield [self::delivery('first')];
            throw new \RuntimeException('Rendering failed');
        })();
        try {
            $store->enqueueBatches($batches, 'scope');
            self::fail('The failure must propagate.');
        } catch (\RuntimeException $e) {
            self::assertSame('Rendering failed', $e->getMessage());
        }
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_deliveries'));
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
        // The rolled-back content is inserted again for the next attempt instead of being taken as present.
        self::assertSame([[hash('sha256', 'first')], [hash('sha256', 'second')]], $store->enqueueBatches([[self::delivery('first')], [self::delivery('second')]], 'scope'));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
        self::assertSame(2, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_deliveries'));
    }

    public function testPruneDeletesOnlyFinishedRowsPastTheCutoff(): void
    {
        $em = self::manager();
        $db = $em->getConnection();
        $store = new DeliveryStore($em);
        $store->install();
        $old = time() - 31 * 86400;
        $rows = [
            'accepted old' => ['accepted', 1, $old, true],
            'unknown old' => ['unknown', 1, $old, true],
            'rejected reconciled' => ['rejected', 1, $old, true],
            'rejected unreconciled' => ['rejected', 0, $old, false],
            'accepted recent' => ['accepted', 1, time() - 86400, false],
            'retry old' => ['retry', 0, $old, false],
            'pending old' => ['pending', 0, $old, false],
        ];
        foreach ($rows as $name => [$state, $synced, $updated]) {
            $delivery = self::delivery($name);
            // One content per delivery, so each content lives exactly as long as its delivery.
            $delivery['common']['Name'] = $name;
            $store->enqueue($delivery, 'scope');
            $db->executeStatement('UPDATE ses_bulk_deliveries SET state = ?, synced = ?, updated_at = ? WHERE id = ?', [$state, $synced, $updated, $delivery['id']]);
        }
        $db->executeStatement('UPDATE ses_bulk_contents SET created_at = ?', [$old]);

        // A batch size of 1 walks every row in its own batch.
        self::assertSame(['deliveries' => 3, 'contents' => 3], $store->prune(30, 1));
        $kept = array_filter($rows, static fn (array $row): bool => !$row[3]);
        self::assertEqualsCanonicalizing(array_map(static fn (string $name): string => hash('sha256', $name), array_keys($kept)), $db->fetchFirstColumn('SELECT id FROM ses_bulk_deliveries'));
        self::assertSame(4, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
        self::assertSame(['deliveries' => 0, 'contents' => 0], $store->prune(30));

        // An old content that a new message uses again gets a fresh created_at, so prune keeps it once its deliveries are gone.
        $again = self::delivery('again');
        $again['common']['Name'] = 'rejected unreconciled';
        $store->enqueueBatches([[$again]], 'scope');
        self::assertSame(4, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
        $db->executeStatement('UPDATE ses_bulk_deliveries SET state = ?, synced = 1, updated_at = ? WHERE id IN (?, ?)', ['accepted', $old, $again['id'], hash('sha256', 'rejected unreconciled')]);
        self::assertSame(['deliveries' => 2, 'contents' => 0], $store->prune(30));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents WHERE created_at > ?', [$old]));
    }
}
