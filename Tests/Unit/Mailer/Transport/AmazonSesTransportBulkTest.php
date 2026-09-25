<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Transport;

use Aws\Result;
use Aws\SesV2\SesV2Client;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use GuzzleHttp\Promise\Create;
use Mautic\CoreBundle\Helper\PathsHelper;
use Mautic\EmailBundle\Mailer\Message\MauticMessage;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\BulkSender;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\DeliveryStore;
use MauticPlugin\AmazonSesBundle\Mailer\Transport\AmazonSesTransport;
use MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk\BulkSenderTest;
use MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Bulk\DeliveryStoreTest;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;
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
            static fn (array $call): array => array_values(array_filter([self::A, self::B], static fn (string $email): bool => str_contains($call[1]['Content']['Raw']['Data'], $email))),
            $this->calls
        );
        sort($recipients);
        self::assertSame([[self::A], [self::B]], $recipients);
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
        self::assertStringContainsString(self::B, $this->calls[1][1]['Content']['Raw']['Data']);
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

    private function transport(array $settings = [], bool $bulkServices = true): AmazonSesTransport
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
            new NullLogger(),
            $settings + ['maxSendRate' => 80, 'batchMultiplier' => 10, 'bulk' => 'auto', 'bulkBatchSize' => 50],
            $bulkServices ? $this->store : null,
            $bulkServices ? new BulkSender($this->store, new NullLogger()) : null,
        );
    }

    private function message(array $tokensB = []): MauticMessage
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
        $message->addMetadata(self::A, ['name' => 'Reader A', 'emailId' => 42, 'hashId' => 'hash-a', 'tokens' => self::tokens('a')]);
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
