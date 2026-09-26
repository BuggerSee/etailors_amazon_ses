<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\E2E;

use MauticPlugin\AmazonSesBundle\Tests\E2E\FakeSesServer;
use PHPUnit\Framework\TestCase;

class FakeSesServerTest extends TestCase
{
    public function testAccountReportsConfiguredSendRate(): void
    {
        $response = (new FakeSesServer(25))->handle('GET', '/v2/email/account', '');

        self::assertSame(200, $response['status']);
        self::assertSame('application/json', $response['headers']['Content-Type']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $response['headers']['x-amzn-RequestId']);
        self::assertSame([
            'SendQuota'               => ['Max24HourSend' => 50000, 'MaxSendRate' => 25, 'SentLast24Hours' => 0],
            'SendingEnabled'          => true,
            'ProductionAccessEnabled' => true,
        ], json_decode($response['body'], true));
    }

    public function testRawSendReturnsMessageIdAndIsLogged(): void
    {
        $log = sys_get_temp_dir().'/fake-ses-test-'.bin2hex(random_bytes(8)).'.jsonl';
        $request = ['Content' => ['Raw' => ['Data' => base64_encode('raw mime')]], 'Destination' => ['ToAddresses' => ['a@example.test']]];

        try {
            $response = (new FakeSesServer(80, $log))->handle('POST', '/v2/email/outbound-emails', json_encode($request));
            $lines = file($log, FILE_IGNORE_NEW_LINES);
        } finally {
            @unlink($log);
        }

        self::assertSame(200, $response['status']);
        $body = json_decode($response['body'], true);
        self::assertMatchesRegularExpression('/^fake-[0-9a-f]{32}$/', $body['MessageId']);
        self::assertCount(1, $lines);
        $entry = json_decode($lines[0], true);
        self::assertIsInt($entry['time']);
        unset($entry['time']);
        self::assertSame(['method' => 'POST', 'path' => '/v2/email/outbound-emails', 'status' => 200, 'request' => $request, 'response' => $body], $entry);
    }

    public function testBulkReturnsOneResultPerEntryInOrder(): void
    {
        $response = (new FakeSesServer())->handle('POST', '/v2/email/outbound-bulk-emails', self::bulkBody(['ok@example.test', 'Some One <TRANSIENT@example.test>', 'rejected@example.test', 'throttled@example.test']));

        self::assertSame(200, $response['status']);
        $results = json_decode($response['body'], true)['BulkEmailEntryResults'];
        self::assertCount(4, $results);
        self::assertSame('SUCCESS', $results[0]['Status']);
        self::assertMatchesRegularExpression('/^fake-[0-9a-f]{32}$/', $results[0]['MessageId']);
        self::assertSame([
            ['Status' => 'TRANSIENT_FAILURE', 'Error' => 'Injected'],
            ['Status' => 'MESSAGE_REJECTED', 'Error' => 'Injected'],
            ['Status' => 'ACCOUNT_THROTTLED', 'Error' => 'Injected'],
        ], array_slice($results, 1));
    }

    public function testFlakyAddressFailsOnlyItsFirstRequest(): void
    {
        $log = sys_get_temp_dir().'/fake-ses-test-'.bin2hex(random_bytes(8)).'.jsonl';

        try {
            // A new server per request, as under PHP's built-in web server: the state must live in the file.
            $first = (new FakeSesServer(80, $log))->handle('POST', '/v2/email/outbound-bulk-emails', self::bulkBody(['flaky@one.example.test']));
            $second = (new FakeSesServer(80, $log))->handle('POST', '/v2/email/outbound-bulk-emails', self::bulkBody(['FLAKY@one.example.test', 'Flaky <flaky@two.example.test>', 'ok@example.test']));
            $third = (new FakeSesServer(80, $log))->handle('POST', '/v2/email/outbound-bulk-emails', self::bulkBody(['flaky@two.example.test']));
            self::assertFileExists($log.'.state.json');
        } finally {
            @unlink($log);
            @unlink($log.'.state.json');
        }

        self::assertSame(['TRANSIENT_FAILURE'], self::statuses($first));
        self::assertSame(['SUCCESS', 'TRANSIENT_FAILURE', 'SUCCESS'], self::statuses($second));
        self::assertSame(['SUCCESS'], self::statuses($third));
    }

    public function testHttp500RecipientFailsTheWholeBulkRequest(): void
    {
        $response = (new FakeSesServer())->handle('POST', '/v2/email/outbound-bulk-emails', self::bulkBody(['ok@example.test', 'http500@example.test']));

        self::assertSame(500, $response['status']);
        self::assertSame(['message' => 'Injected internal error'], json_decode($response['body'], true));
    }

    public function testBulkWithoutTemplateContentIsBadRequest(): void
    {
        $body = json_decode(self::bulkBody(['ok@example.test']), true);
        unset($body['DefaultContent']['Template']['TemplateContent']);

        $response = (new FakeSesServer())->handle('POST', '/v2/email/outbound-bulk-emails', json_encode($body));

        self::assertSame(400, $response['status']);
        self::assertSame('BadRequestException', $response['headers']['x-amzn-ErrorType']);
        self::assertArrayHasKey('message', json_decode($response['body'], true));
    }

    public function testUnknownRouteIsNotFound(): void
    {
        $response = (new FakeSesServer())->handle('GET', '/v2/email/templates', '');

        self::assertSame(404, $response['status']);
        self::assertSame('application/json', $response['headers']['Content-Type']);
        self::assertSame(['message' => 'Unknown operation'], json_decode($response['body'], true));
    }

    /**
     * @param array{status: int, headers: array<string, string>, body: string} $response
     *
     * @return list<string>
     */
    private static function statuses(array $response): array
    {
        self::assertSame(200, $response['status']);

        return array_column(json_decode($response['body'], true)['BulkEmailEntryResults'], 'Status');
    }

    /**
     * @param list<string> $recipients
     */
    private static function bulkBody(array $recipients): string
    {
        return json_encode([
            'FromEmailAddress' => 'sender@example.test',
            'DefaultContent'   => ['Template' => ['TemplateContent' => ['Subject' => 'Hi {{name}}', 'Html' => '<p>Hi</p>'], 'TemplateData' => '{}']],
            'BulkEmailEntries' => array_map(static fn (string $to): array => ['Destination' => ['ToAddresses' => [$to]]], $recipients),
        ]);
    }
}
