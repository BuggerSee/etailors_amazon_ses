<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\Persistence\Mapping\Driver\StaticPHPDriver;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\DeliveryStore;
use PHPUnit\Framework\TestCase;

class DeliveryStoreTest extends TestCase
{
    public static function manager(): EntityManager
    {
        $config = ORMSetup::createConfiguration(true);
        $config->setMetadataDriverImpl(new StaticPHPDriver([dirname(__DIR__, 4).'/Entity']));

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
        self::assertSame(0, $store->syncFailures());
        $em->getConnection()->insert('email_stats', ['id' => 1, 'email_id' => 42, 'tracking_hash' => $delivery['tracking_hash'], 'is_failed' => 0]);
        self::assertSame(1, $store->syncFailures());
        self::assertSame(1, (int) $em->getConnection()->fetchOne('SELECT is_failed FROM email_stats'));
        self::assertSame(0, $store->syncFailures());
    }
}
