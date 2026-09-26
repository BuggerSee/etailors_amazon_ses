<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Transport;

use Aws\Result;
use Aws\SesV2\SesV2Client;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\Promise;
use Mautic\CoreBundle\Helper\PathsHelper;
use Mautic\EmailBundle\Mailer\Message\MauticMessage;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\BulkSender;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\DeliveryStore;
use MauticPlugin\AmazonSesBundle\Mailer\Transport\AmazonSesTransport;
use MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk\BulkSenderTest;
use MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk\DeliveryStoreTest;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mime\Address;

class AmazonSesTransportBulkTest extends TestCase
{
    private const A = 'a@example.test';
    private const B = 'b@example.test';

    /** @var list<array{0: string, 1: array<string, mixed>}> */
    private array $calls = [];
    private SesV2Client $client;
    private EntityManager $em;
    private DeliveryStore $store;
    private string $cache;

    protected function setUp(): void
    {
        $this->client = BulkSenderTest::client(function ($command) {
            $this->calls[] = [$command->getName(), $command->toArray()];
            if ('SendBulkEmail' !== $command->getName()) {
                return Create::promiseFor(new Result(['MessageId' => 'raw-'.count($this->calls)]));
            }
            $results = [];
            foreach (array_keys($command['BulkEmailEntries']) as $i) {
                $results[] = ['Status' => 'SUCCESS', 'MessageId' => 'bulk-'.count($this->calls).'-'.$i];
            }

            return Create::promiseFor(new Result(['BulkEmailEntryResults' => $results]));
        });
        $this->em = DeliveryStoreTest::manager();
        $this->store = new DeliveryStore($this->em);
        $this->store->install();
        $this->cache = sys_get_temp_dir().'/ses-transport-test-'.bin2hex(random_bytes(8));
        mkdir($this->cache);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->cache.'/*') ?: []);
        rmdir($this->cache);
    }

    public function testEligibleMessageIsSubmittedAsOneSharedTemplateRequest(): void
    {
        $message = $this->message();
        $sent = $this->transport()->send($message);

        self::assertSame(['SendBulkEmail'], array_column($this->calls, 0));
        $request = $this->calls[0][1];
        self::assertSame('newsletter', $request['ConfigurationSetName']);
        self::assertArrayNotHasKey('EmailTags', $request);
        $html = $request['DefaultContent']['Template']['TemplateContent']['Html'];
        self::assertStringContainsString('{{v_', $html);
        self::assertStringNotContainsString(self::A, $html);
        self::assertStringNotContainsString(self::B, $html);
        self::assertSame('{}', $request['DefaultContent']['Template']['TemplateData']);
        self::assertCount(2, $request['BulkEmailEntries']);

        $entry = $request['BulkEmailEntries'][0];
        self::assertSame([(new Address(self::A, 'Reader A'))->toString()], $entry['Destination']['ToAddresses']);
        $data = json_decode($entry['ReplacementEmailContent']['ReplacementTemplate']['ReplacementTemplateData'], true, 512, JSON_THROW_ON_ERROR);
        self::assertContains(self::A, $data);
        self::assertContains(self::tokens('a')['{unsubscribe_text}'], $data);
        self::assertNotContains(self::B, $data);
        self::assertContains(['Name' => 'List-Unsubscribe', 'Value' => '<'.self::tokens('a')['{unsubscribe_url}'].'>'], $entry['ReplacementHeaders']);
        self::assertNotContains('X-SES-CONFIGURATION-SET', array_column($entry['ReplacementHeaders'], 'Name'));
        self::assertContains(['Name' => 'X-EMAIL-ID', 'Value' => '42'], $entry['ReplacementTags']);
        $ids = array_map(static fn (array $entry): string => array_column($entry['ReplacementTags'], 'Value', 'Name')['mautic_delivery_id'], $request['BulkEmailEntries']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $ids[0]);
        self::assertNotSame($ids[0], $ids[1]);

        self::assertSame([['bulk', 'accepted', '', 2]], $this->recipients());
        // The message the transport worked on keeps its tokens and metadata.
        $original = $sent->getOriginalMessage();
        self::assertSame($message->getMetadata(), $original->getMetadata());
        self::assertStringContainsString('{contactfield=email}', $original->getHtmlBody());
    }

    public function testAttachmentFallsBackToConcurrentRawPath(): void
    {
        $this->transport()->send($this->message()->attach('data', 'file.txt'));

        self::assertSame(['SendEmail', 'SendEmail'], array_column($this->calls, 0));
        $recipients = array_map(
            static fn (array $call): array => array_values(array_filter([self::A, self::B], static fn (string $email): bool => str_contains($call[1]['Content']['Raw']['Data'], '<'.$email.'>'))),
            $this->calls
        );
        sort($recipients);
        self::assertSame([[self::A], [self::B]], $recipients);
        self::assertSame([], $this->recipients());
    }

    public function testSenderHeaderEqualToFromKeepsTheBulkPath(): void
    {
        // Mautic 7 sets Sender to the From address on every message. The address is compared case-insensitively.
        $this->transport()->send($this->message()->sender(new Address('NEWS@example.test', 'Mautic')));

        self::assertSame(['SendBulkEmail'], array_column($this->calls, 0));
        $entries = $this->calls[0][1]['BulkEmailEntries'];
        self::assertCount(2, $entries);
        foreach ($entries as $entry) {
            self::assertNotContains('sender', array_map('strtolower', array_column($entry['ReplacementHeaders'], 'Name')));
        }
        self::assertSame([['bulk', 'accepted', '', 2]], $this->recipients());
    }

    public function testSenderHeaderDifferentFromFromFallsBackToRaw(): void
    {
        $this->transport()->send($this->message()->sender('other@example.test'));

        self::assertSame(['SendEmail', 'SendEmail'], array_column($this->calls, 0));
        foreach ($this->calls as [, $request]) {
            self::assertMatchesRegularExpression('/^Sender: .*other@example\.test/m', $request['Content']['Raw']['Data']);
        }
        self::assertSame([], $this->recipients());
    }

    public function testRecipientWithoutDeliveryIdentityUsesRawPath(): void
    {
        $message = $this->message();
        // Mautic always sets the key; it is null when no tracking hash exists.
        $message->addMetadata(self::B, ['hashId' => null] + $message->getMetadata()[self::B]);
        $this->transport()->send($message);

        self::assertSame(['SendEmail', 'SendEmail'], array_column($this->calls, 0));
        self::assertSame([], $this->recipients());
    }

    public function testBulkOffKeepsRawPath(): void
    {
        $this->transport(['bulk' => 'off'], false)->send($this->message());

        self::assertSame(['SendEmail', 'SendEmail'], array_column($this->calls, 0));
    }

    public function testPerRecipientIneligibilityUsesPersistedRawFallback(): void
    {
        $this->transport()->send($this->message(['{unsubscribe_text}' => '<a href="https://example.test/u/b">{{Unsubscribe}}</a>']));

        self::assertSame(['SendBulkEmail', 'SendEmail'], array_column($this->calls, 0));
        self::assertCount(1, $this->calls[0][1]['BulkEmailEntries']);
        self::assertStringContainsString('<'.self::B.'>', $this->calls[1][1]['Content']['Raw']['Data']);
        self::assertSame([['bulk', 'accepted', '', 1], ['raw', 'accepted', 'literal_template_delimiters', 1]], $this->recipients());
    }

    public function testRetryBulkResubmitsOnlyDueDeliveries(): void
    {
        $scope = BulkSender::scope($this->client);
        $due = $this->store->enqueue(DeliveryStoreTest::delivery('due'), $scope);
        $done = $this->store->enqueue(DeliveryStoreTest::delivery('done'), $scope);
        $this->store->complete($this->store->claim($done, $scope, 'worker'), 'accepted', '', 'ses-done');
        $this->em->getConnection()->executeStatement('UPDATE ses_bulk_deliveries SET next_attempt = 0');

        self::assertSame(1, $this->transport()->retryBulk());
        self::assertSame(['SendBulkEmail'], array_column($this->calls, 0));
        $entries = $this->calls[0][1]['BulkEmailEntries'];
        self::assertCount(1, $entries);
        self::assertSame($due, array_column($entries[0]['ReplacementTags'], 'Value', 'Name')['mautic_delivery_id']);
    }

    /**
     * @dataProvider windows
     */
    public function testRequestsOfOneMessageArePipelined(int $concurrency, array $expected): void
    {
        $answeredAtCall = $this->deferResponses();
        // One recipient per request, so the two recipients need two requests.
        $this->transport(['bulkBatchSize' => 1, 'bulkConcurrency' => $concurrency])->send($this->message());

        self::assertSame(['SendBulkEmail', 'SendBulkEmail'], array_column($this->calls, 0));
        self::assertSame($expected, $answeredAtCall->getArrayCopy());
        self::assertSame([['bulk', 'accepted', '', 2]], $this->recipients());
    }

    public static function windows(): array
    {
        return [
            // The second request reaches SES before the first response arrives.
            'window of two' => [2, [0, 0]],
            // Without a window the second request waits for the first response.
            'window of one' => [1, [0, 1]],
        ];
    }

    public function testOutboxRetryIsPipelined(): void
    {
        $answeredAtCall = $this->deferResponses();
        $scope = BulkSender::scope($this->client);
        $this->store->enqueue(DeliveryStoreTest::delivery('a'), $scope);
        $this->store->enqueue(DeliveryStoreTest::delivery('b'), $scope);

        self::assertSame(2, $this->transport(['bulkBatchSize' => 1, 'bulkConcurrency' => 2])->retryBulk());
        self::assertSame(['SendBulkEmail', 'SendBulkEmail'], array_column($this->calls, 0));
        self::assertSame([0, 0], $answeredAtCall->getArrayCopy());
        self::assertSame([['bulk', 'accepted', '', 2]], $this->recipients());
    }

    public function testFailureBeforeTheCommitReachesMauticAndLeavesNothingBehind(): void
    {
        // Saving the second recipient fails, for example with a lock wait timeout.
        $this->em->getConnection()->executeStatement("CREATE TRIGGER fail_b BEFORE INSERT ON ses_bulk_deliveries WHEN NEW.tracking_hash = 'hash-b' BEGIN SELECT RAISE(ABORT, 'Lock wait timeout exceeded'); END");

        // Symfony throttles a failed send twice, which would wait a second at the transport's one message per second.
        $transport = $this->transport()->setMaxPerSecond(0);
        try {
            $transport->send($this->message());
            self::fail('Mautic must learn that the message failed.');
        } catch (TransportException $e) {
            self::assertStringContainsString('Lock wait timeout exceeded', $e->getMessage());
        }
        // Nothing was submitted and nothing is left that the retry command would send next to Mautic's own resend.
        self::assertSame([], $this->calls);
        self::assertSame(0, (int) $this->em->getConnection()->fetchOne('SELECT COUNT(*) FROM ses_bulk_deliveries'));
        self::assertSame(0, (int) $this->em->getConnection()->fetchOne('SELECT COUNT(*) FROM ses_bulk_contents'));
    }

    /**
     * @dataProvider failuresAfterSubmission
     */
    public function testFailureAfterTheFirstRequestIsLeftToTheOutbox(string $trigger, array $operations, array $stateB): void
    {
        $this->em->getConnection()->executeStatement($trigger);
        $logger = new class() extends AbstractLogger {
            public array $errors = [];

            public function log($level, $message, array $context = []): void
            {
                if (LogLevel::ERROR === $level) {
                    $this->errors[] = (string) $message;
                }
            }
        };

        // Two requests, one at a time: the first is accepted before the second batch fails. Mautic keeps its statistics,
        // so it will not send the message again under new tracking hashes.
        $this->transport(['bulkBatchSize' => 1, 'bulkConcurrency' => 1], true, $logger)->send($this->message());

        self::assertSame(['SES bulk sending stopped after the recipients were saved; mautic:ses:bulk retry submits the ones left.'], $logger->errors);
        self::assertSame($operations, array_column($this->calls, 0));
        $rows = $this->em->getConnection()->fetchAllAssociativeIndexed('SELECT tracking_hash, state, reason, attempts FROM ses_bulk_deliveries');
        self::assertSame('accepted', $rows['hash-a']['state']);
        self::assertSame($stateB, [$rows['hash-b']['state'], $rows['hash-b']['reason'], (int) $rows['hash-b']['attempts']]);
    }

    public static function failuresAfterSubmission(): array
    {
        return [
            // Never submitted: released for the retry command without spending an attempt.
            'before the second request' => ["CREATE TRIGGER fail_b BEFORE UPDATE OF requests ON ses_bulk_contents WHEN NEW.requests = 2 BEGIN SELECT RAISE(ABORT, 'Lock wait timeout exceeded'); END", ['SendBulkEmail'], ['retry', 'local_preflight_failure', 0]],
            // Submitted, outcome not recorded: the claim expires to unknown and is never sent again.
            'recording the second outcome' => ["CREATE TRIGGER fail_b BEFORE UPDATE ON ses_bulk_deliveries WHEN OLD.tracking_hash = 'hash-b' AND OLD.state = 'sending' BEGIN SELECT RAISE(ABORT, 'Server has gone away'); END", ['SendBulkEmail', 'SendBulkEmail'], ['sending', '', 1]],
        ];
    }

    public function testTokenizedHeaderThatResolvesToNothingIsLeftOut(): void
    {
        $message = $this->message(['{contactfield=company}' => ''], ['{contactfield=company}' => 'ACME']);
        $message->getHeaders()->addTextHeader('X-Company', '{contactfield=company}');
        $this->transport()->send($message);

        // As Mautic core does for custom headers; SES refuses an empty header value for the whole request.
        self::assertSame(['SendBulkEmail'], array_column($this->calls, 0));
        [$a, $b] = array_map(static fn (array $entry): array => array_column($entry['ReplacementHeaders'], 'Value', 'Name'), $this->calls[0][1]['BulkEmailEntries']);
        self::assertSame('ACME', $a['X-Company']);
        self::assertArrayNotHasKey('X-Company', $b);
        self::assertSame([['bulk', 'accepted', '', 2]], $this->recipients());
    }

    public function testHeaderValueThatSesRefusesSendsThatRecipientRaw(): void
    {
        // Symfony leaves a tab unencoded, but SES only accepts printable ASCII.
        $message = $this->message(['{contactfield=company}' => "Acme\tInc"], ['{contactfield=company}' => 'ACME']);
        $message->getHeaders()->addTextHeader('X-Company', '{contactfield=company}');
        $this->transport()->send($message);

        self::assertSame(['SendBulkEmail', 'SendEmail'], array_column($this->calls, 0));
        self::assertCount(1, $this->calls[0][1]['BulkEmailEntries']);
        self::assertStringContainsString('<'.self::B.'>', $this->calls[1][1]['Content']['Raw']['Data']);
        self::assertSame([['bulk', 'accepted', '', 1], ['raw', 'accepted', 'header_value', 1]], $this->recipients());
    }

    /**
     * @dataProvider feedbackAddresses
     */
    public function testReturnPathIsSentAsFeedbackForwardingAddress(?string $feedbackHeader, array $operations): void
    {
        // Mautic sets Return-Path from the custom return path (mailer_return_path) or a bounce address.
        $message = $this->message()->returnPath('bounces@example.test');
        if (null !== $feedbackHeader) {
            $message->getHeaders()->addTextHeader('X-SES-FEEDBACK-FORWARDING-EMAIL-ADDRESS', $feedbackHeader);
        }
        $this->transport()->send($message);

        self::assertSame($operations, array_column($this->calls, 0));
        foreach ($this->calls as [$operation, $request]) {
            if ('SendBulkEmail' === $operation) {
                self::assertSame('bounces@example.test', $request['FeedbackForwardingEmailAddress']);
                foreach ($request['BulkEmailEntries'] as $entry) {
                    self::assertNotContains('return-path', array_map('strtolower', array_column($entry['ReplacementHeaders'], 'Name')));
                }
            } else {
                self::assertStringContainsString('Return-Path: <bounces@example.test>', $request['Content']['Raw']['Data']);
            }
        }
    }

    public static function feedbackAddresses(): array
    {
        return [
            'return path only' => [null, ['SendBulkEmail']],
            'same feedback address' => ['Bounces@example.test', ['SendBulkEmail']],
            // Which of the two SES would use is not documented, so the email is sent as before.
            'different feedback address' => ['feedback@example.test', ['SendEmail', 'SendEmail']],
        ];
    }

    /**
     * @dataProvider windowLimits
     */
    public function testWindowCarriesAtMostOneSecondOfTheSendRate(int $concurrency, array $entries): void
    {
        // A full bucket, so the test does not wait for tokens.
        file_put_contents($this->cache.'/ses_token_bucket.json', json_encode(['tokens' => 4.0, 'last_time' => microtime(true)]));
        $this->transport(['maxSendRate' => 4, 'bulkConcurrency' => $concurrency])->send($this->message());

        self::assertSame($entries, array_map(static fn (array $call): int => count($call[1]['BulkEmailEntries']), $this->calls));
        self::assertSame([['bulk', 'accepted', '', 2]], $this->recipients());
    }

    public static function windowLimits(): array
    {
        return [
            // Two requests in flight may leave together: 2 x 2 recipients is one second at 4/s.
            'window of two' => [2, [2]],
            // Four requests in flight: one recipient each.
            'window of four' => [4, [1, 1]],
        ];
    }

    private function transport(array $settings = [], bool $bulkServices = true, ?LoggerInterface $logger = null): AmazonSesTransport
    {
        $paths = $this->createMock(PathsHelper::class);
        $paths->method('getSystemPath')->with('cache', true)->willReturn($this->cache);
        // Mautic's EmailRepository requires a ManagerRegistry, so the Email lookup is stubbed (no entity: no From/Reply-To override).
        $emails = $this->createMock(EntityManagerInterface::class);
        $emails->method('getRepository')->willReturn($this->createMock(EntityRepository::class));

        return new AmazonSesTransport(
            $this->client,
            $emails,
            $paths,
            new EventDispatcher(),
            $logger ?? new NullLogger(),
            $settings + ['maxSendRate' => 80, 'batchMultiplier' => 10, 'bulk' => 'auto', 'bulkBatchSize' => 50],
            $bulkServices ? $this->store : null,
            $bulkServices ? new BulkSender($this->store, new NullLogger()) : null,
        );
    }

    /**
     * Responses stay open until the sender waits; each wait answers the oldest open request, as if responses arrived in order.
     * Every request is answered with one successful entry, so requests must carry one recipient each.
     *
     * @return \ArrayObject<int, int> for each request, the number of answered requests when it reached SES
     */
    private function deferResponses(): \ArrayObject
    {
        $open = [];
        $answered = 0;
        $answeredAtCall = new \ArrayObject();
        $wait = static function () use (&$open, &$answered): void {
            $open[$answered]->resolve(new Result(['BulkEmailEntryResults' => [['Status' => 'SUCCESS', 'MessageId' => 'bulk-'.$answered]]]));
            ++$answered;
        };
        $this->client = BulkSenderTest::client(function ($command) use (&$open, &$answered, $answeredAtCall, $wait): Promise {
            $this->calls[] = [$command->getName(), $command->toArray()];
            $answeredAtCall[] = $answered;

            return $open[] = new Promise($wait);
        });

        return $answeredAtCall;
    }

    private function message(array $tokensB = [], array $tokensA = []): MauticMessage
    {
        $message = (new MauticMessage())
            ->from(new Address('news@example.test', 'Newsroom'))
            ->to(new Address(self::A, 'Reader A'), new Address(self::B, 'Reader B'))
            ->subject('News')
            ->html('<p>News</p><p>{contactfield=email}</p>{unsubscribe_text}<img src="{tracking_pixel}">')
            ->text('News {contactfield=email}');
        $message->getHeaders()->addTextHeader('X-EMAIL-ID', '42');
        $message->getHeaders()->addTextHeader('X-SES-CONFIGURATION-SET', 'newsletter');
        $message->getHeaders()->addTextHeader('List-Unsubscribe', '<https://example.test/old>');
        $message->addMetadata(self::A, ['name' => 'Reader A', 'emailId' => 42, 'hashId' => 'hash-a', 'tokens' => $tokensA + self::tokens('a')]);
        $message->addMetadata(self::B, ['name' => 'Reader B', 'emailId' => 42, 'hashId' => 'hash-b', 'tokens' => $tokensB + self::tokens('b')]);

        return $message;
    }

    private static function tokens(string $contact): array
    {
        return [
            '{contactfield=email}' => $contact.'@example.test',
            '{unsubscribe_text}' => '<a href="https://example.test/u/'.$contact.'">Unsubscribe '.$contact.'</a>',
            '{unsubscribe_url}' => 'https://example.test/u/'.$contact,
            '{tracking_pixel}' => 'https://example.test/p/'.$contact.'.gif',
        ];
    }

    /** @return list<array{0: string, 1: string, 2: string, 3: int}> operation, state, reason, recipients */
    private function recipients(): array
    {
        $rows = array_map(static fn (array $row): array => [$row['operation'], $row['state'], $row['reason'], (int) $row['recipients']], $this->store->summary(42)['recipients']);
        sort($rows);

        return $rows;
    }
}
