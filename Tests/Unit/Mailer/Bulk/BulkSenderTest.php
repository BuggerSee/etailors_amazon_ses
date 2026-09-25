<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk;

use Aws\Exception\AwsException;
use Aws\Result;
use Aws\SesV2\SesV2Client;
use Doctrine\ORM\EntityManager;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\Promise;
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

    public function testWindowLimitsInFlightRequests(): void
    {
        $resolvedAtCall = $this->sendThreeGroups(2);
        // The second request is submitted before any response; the third waits for a free slot.
        self::assertSame(0, $resolvedAtCall[1]);
        self::assertGreaterThanOrEqual(1, $resolvedAtCall[2]);

        // Without a window each request is submitted only after the previous one resolved.
        self::assertSame([0, 1, 2], $this->sendThreeGroups(1));
    }

    public function testFailuresAreAttributedToTheirOwnGroup(): void
    {
        $client = self::client(static function ($command) {
            if ('News a' === $command['DefaultContent']['Template']['TemplateContent']['Subject']) {
                return Create::rejectionFor(new AwsException('Slow down', $command, ['code' => 'TooManyRequestsException']));
            }

            return Create::promiseFor(new Result(['BulkEmailEntryResults' => [['Status' => 'SUCCESS', 'MessageId' => 'b-id']]]));
        });
        $em = DeliveryStoreTest::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $ids = self::enqueueGroups($store, $client, ['a', 'b']);
        (new BulkSender($store, new NullLogger()))->send($client, $ids, static fn () => null, 2);
        self::assertSame('retry', self::state($em, $ids[0]));
        self::assertSame('accepted', self::state($em, $ids[1]));
    }

    public function testPreflightFailureStillRecordsSubmittedRequests(): void
    {
        $client = self::client(static fn () => Create::promiseFor(new Result(['BulkEmailEntryResults' => [['Status' => 'SUCCESS', 'MessageId' => 'a-id']]])));
        $em = DeliveryStoreTest::manager();
        $store = new DeliveryStore($em);
        $store->install();
        $ids = self::enqueueGroups($store, $client, ['a', 'b']);
        $calls = 0;
        $acquire = static function () use (&$calls): void {
            if (2 === ++$calls) {
                throw new \RuntimeException('Token bucket unavailable');
            }
        };
        try {
            (new BulkSender($store, new NullLogger()))->send($client, $ids, $acquire, 2);
            self::fail('The preflight failure must propagate.');
        } catch (\RuntimeException $e) {
            self::assertSame('Token bucket unavailable', $e->getMessage());
        }
        // The first request was already in flight; its outcome is recorded, not left in 'sending'.
        self::assertSame('accepted', self::state($em, $ids[0]));
        self::assertSame('retry', self::state($em, $ids[1]));
    }

    public static function client(callable $handler): SesV2Client
    {
        return new SesV2Client(['version' => 'latest', 'region' => 'eu-central-1', 'credentials' => ['key' => 'test', 'secret' => 'test'], 'handler' => $handler]);
    }

    /** @return list<int> the number of resolved requests when each request reached SES */
    private function sendThreeGroups(int $concurrency): array
    {
        $promises = [];
        $resolved = 0;
        $resolvedAtCall = [];
        // Waiting on any request completes the oldest unresolved one, like responses arriving in order.
        $wait = static function () use (&$promises, &$resolved): void {
            $promises[$resolved]->resolve(new Result(['BulkEmailEntryResults' => [['Status' => 'SUCCESS', 'MessageId' => 'id-'.$resolved]]]));
            ++$resolved;
        };
        $client = self::client(static function () use (&$promises, &$resolved, &$resolvedAtCall, $wait): Promise {
            $resolvedAtCall[] = $resolved;

            return $promises[] = new Promise($wait);
        });
        $store = new DeliveryStore(DeliveryStoreTest::manager());
        $store->install();
        $ids = self::enqueueGroups($store, $client, ['a', 'b', 'c']);
        (new BulkSender($store, new NullLogger()))->send($client, $ids, static fn () => null, $concurrency);
        self::assertSame([['accepted', 3]], array_map(static fn (array $row): array => [$row['state'], (int) $row['recipients']], $store->summary()['recipients']));

        return $resolvedAtCall;
    }

    /** @return list<string> one delivery per name, each with its own common content and therefore its own request */
    private static function enqueueGroups(DeliveryStore $store, SesV2Client $client, array $names): array
    {
        $ids = [];
        foreach ($names as $name) {
            $delivery = DeliveryStoreTest::delivery($name);
            $delivery['common']['DefaultContent']['Template']['TemplateContent']['Subject'] = 'News '.$name;
            $ids[] = $store->enqueue($delivery, BulkSender::scope($client));
        }

        return $ids;
    }

    private static function state(EntityManager $em, string $id): string
    {
        return $em->getConnection()->fetchOne('SELECT state FROM ses_bulk_deliveries WHERE id = ?', [$id]);
    }
}
