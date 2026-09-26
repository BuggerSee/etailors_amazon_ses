<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\E2E;

/**
 * Minimal SES v2 HTTP API stand-in for offline end-to-end runs (see fake-ses-server.php).
 *
 * Bulk entries fail on demand by the local part of their first recipient:
 * transient@, throttled@ and rejected@ fail that entry; http500@ fails the whole request.
 * flaky@ fails the first request for that address with TRANSIENT_FAILURE and succeeds in every later one;
 * the addresses already seen are kept in <log>.state.json (or in the system temp directory without a log).
 */
final class FakeSesServer
{
    private const INJECTED_STATUSES = [
        'transient' => 'TRANSIENT_FAILURE',
        'throttled' => 'ACCOUNT_THROTTLED',
        'rejected'  => 'MESSAGE_REJECTED',
    ];

    public function __construct(private int $maxSendRate = 80, private ?string $logFile = null)
    {
    }

    /**
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    public function handle(string $method, string $path, string $body): array
    {
        $request = json_decode($body, true);
        [$status, $response] = $this->route($method, $path, is_array($request) ? $request : []);
        $headers = ['Content-Type' => 'application/json', 'x-amzn-RequestId' => self::requestId()];
        if (400 === $status) {
            $headers['x-amzn-ErrorType'] = 'BadRequestException';
        }

        if (null !== $this->logFile) {
            $line = ['time' => time(), 'method' => $method, 'path' => $path, 'status' => $status, 'request' => $request, 'response' => $response];
            file_put_contents($this->logFile, json_encode($line, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n", FILE_APPEND | LOCK_EX);
        }

        return ['status' => $status, 'headers' => $headers, 'body' => json_encode($response, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)];
    }

    /**
     * @param array<mixed> $request
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    private function route(string $method, string $path, array $request): array
    {
        return match ($method.' '.$path) {
            'GET /v2/email/account' => [200, [
                'SendQuota'               => ['Max24HourSend' => 50000, 'MaxSendRate' => $this->maxSendRate, 'SentLast24Hours' => 0],
                'SendingEnabled'          => true,
                'ProductionAccessEnabled' => true,
            ]],
            'POST /v2/email/outbound-emails'      => $this->sendEmail($request),
            'POST /v2/email/outbound-bulk-emails' => $this->sendBulkEmail($request),
            default                               => [404, ['message' => 'Unknown operation']],
        };
    }

    /**
     * @param array<mixed> $request
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    private function sendEmail(array $request): array
    {
        if (!isset($request['Content'], $request['Destination'])) {
            return [400, ['message' => 'Content and Destination are required']];
        }

        return [200, ['MessageId' => self::messageId()]];
    }

    /**
     * @param array<mixed> $request
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    private function sendBulkEmail(array $request): array
    {
        if (!isset($request['DefaultContent']['Template']['TemplateContent'])) {
            return [400, ['message' => 'DefaultContent.Template.TemplateContent is required']];
        }
        $entries = $request['BulkEmailEntries'] ?? null;
        if (!is_array($entries) || [] === $entries) {
            return [400, ['message' => 'BulkEmailEntries is required']];
        }

        $addresses = [];
        foreach ($entries as $entry) {
            $to = $entry['Destination']['ToAddresses'][0] ?? null;
            if (!is_string($to)) {
                return [400, ['message' => 'Every entry needs Destination.ToAddresses']];
            }
            $addresses[] = self::address($to);
        }
        $localParts = array_map(self::localPart(...), $addresses);

        if (in_array('http500', $localParts, true)) {
            return [500, ['message' => 'Injected internal error']];
        }

        $flaky = array_values(array_filter($addresses, static fn (string $address): bool => 'flaky' === self::localPart($address)));
        $firstSeen = [] === $flaky ? [] : $this->markSeen($flaky);
        $results = [];
        foreach ($localParts as $i => $localPart) {
            $status = isset($firstSeen[$addresses[$i]]) ? 'TRANSIENT_FAILURE' : (self::INJECTED_STATUSES[$localPart] ?? null);
            $results[] = null !== $status
                ? ['Status' => $status, 'Error' => 'Injected']
                : ['Status' => 'SUCCESS', 'MessageId' => self::messageId()];
        }

        return [200, ['BulkEmailEntryResults' => $results]];
    }

    /**
     * Records the addresses in the state file and returns those that had not been seen before.
     *
     * @param list<string> $addresses
     *
     * @return array<string, true>
     */
    private function markSeen(array $addresses): array
    {
        $file = null !== $this->logFile ? $this->logFile.'.state.json' : sys_get_temp_dir().'/fake-ses-state.json';
        $handle = fopen($file, 'c+');
        if (false === $handle) {
            throw new \RuntimeException('Cannot open the fake SES state file '.$file);
        }

        try {
            flock($handle, LOCK_EX);
            $seen = json_decode((string) stream_get_contents($handle), true);
            $seen = is_array($seen) ? $seen : [];
            $firstSeen = [];
            foreach ($addresses as $address) {
                if (!isset($seen[$address])) {
                    $seen[$address] = time();
                    $firstSeen[$address] = true;
                }
            }
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode($seen, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }

        return $firstSeen;
    }

    private static function address(string $to): string
    {
        if (preg_match('/<([^>]*)>/', $to, $matches)) {
            $to = $matches[1];
        }

        return strtolower(trim($to));
    }

    private static function localPart(string $address): string
    {
        $at = strrpos($address, '@');

        return false === $at ? $address : substr($address, 0, $at);
    }

    private static function messageId(): string
    {
        return 'fake-'.bin2hex(random_bytes(16));
    }

    private static function requestId(): string
    {
        $hex = bin2hex(random_bytes(16));

        return implode('-', [substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20)]);
    }
}
