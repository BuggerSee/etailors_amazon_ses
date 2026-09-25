<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk;

use Aws\Exception\AwsException;
use Aws\Result;
use Aws\SesV2\SesV2Client;
use GuzzleHttp\Promise\Create;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\BulkSender;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\DeliveryStore;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class BulkSenderTest extends TestCase
{
    public function testPartialResultsRetryOnlyFailedRecipientsAndChargeQuota(): void
    {
        $calls = [];
        $client = self::client(function ($command) use (&$calls) {
            $calls[] = $command->toArray();
            return Create::promiseFor(new Result(['BulkEmailEntryResults' => 1 === count($calls) ? [
                ['Status' => 'SUCCESS', 'MessageId' => 'first-id'], ['Status' => 'TRANSIENT_FAILURE'],
            ] : [['Status' => 'SUCCESS', 'MessageId' => 'second-id']]]));
        });
        BulkSender::assertSupported($client);
        $em = DeliveryStoreTest::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $scope = BulkSender::scope($client);
        $ids = [$store->enqueue(DeliveryStoreTest::delivery('a'), $scope), $store->enqueue(DeliveryStoreTest::delivery('b'), $scope)];
        $sender = new BulkSender($store, new NullLogger());
        $tokens = [];
        $acquire = static function (int $count) use (&$tokens): void { $tokens[] = $count; };
        $sender->send($client, $ids, $acquire);
        // Replaying the original queue job cannot resend accepted or not-yet-due entries.
        $sender->send($client, $ids, $acquire);
        self::assertCount(1, $calls);
        $em->getConnection()->executeStatement('UPDATE ses_bulk_deliveries SET next_attempt = 0');
        $sender->send($client, $ids, $acquire);
        self::assertSame([2, 1], $tokens);
        self::assertCount(1, $calls[1]['BulkEmailEntries']);
        self::assertSame(0, $calls[0]['@retries']);
        self::assertSame('accepted', $store->summary()['recipients'][0]['state']);
    }

    public function testTimeoutIsUnknownAndNotAutomaticallyRetried(): void
    {
        $calls = 0;
        $client = self::client(function ($command) use (&$calls) {
            ++$calls;
            return Create::rejectionFor(new AwsException('Connection lost', $command, ['connection_error' => true]));
        });
        $store = new DeliveryStore(DeliveryStoreTest::manager());
        $store->install();
        $id = $store->enqueue(DeliveryStoreTest::delivery(), BulkSender::scope($client));
        $sender = new BulkSender($store, new NullLogger());
        $sender->send($client, [$id], static fn () => null);
        $sender->send($client, [$id], static fn () => null);
        self::assertSame(1, $calls);
        self::assertSame('unknown', $store->summary()['recipients'][0]['state']);
    }

    public function testMalformedResponseCannotShiftRecipientResults(): void
    {
        $client = self::client(static fn () => Create::promiseFor(new Result(['BulkEmailEntryResults' => [['Status' => 'SUCCESS', 'MessageId' => 'one']]])));
        $store = new DeliveryStore(DeliveryStoreTest::manager());
        $store->install();
        $ids = [$store->enqueue(DeliveryStoreTest::delivery('a'), BulkSender::scope($client)), $store->enqueue(DeliveryStoreTest::delivery('b'), BulkSender::scope($client))];
        (new BulkSender($store, new NullLogger()))->send($client, $ids, static fn () => null);
        self::assertSame('unknown', $store->summary()['recipients'][0]['state']);
        self::assertSame(2, (int) $store->summary()['recipients'][0]['recipients']);
    }

    public static function client(callable $handler): SesV2Client
    {
        return new SesV2Client(['version' => 'latest', 'region' => 'eu-central-1', 'credentials' => ['key' => 'test', 'secret' => 'test'], 'handler' => $handler]);
    }
}
