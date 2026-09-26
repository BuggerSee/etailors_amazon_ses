<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Helper;

use Aws\Sns\Message;
use Aws\Sns\MessageValidator;
use MauticPlugin\AmazonSesBundle\Helper\SnsCertificateUnavailable;
use MauticPlugin\AmazonSesBundle\Helper\SnsWebhookAuthenticator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class SnsWebhookAuthenticatorTest extends TestCase
{
    private const TOPIC = 'arn:aws:sns:eu-west-1:123456789012:mautic-feedback';
    private const CERTIFICATE_URL = 'https://sns.eu-west-1.amazonaws.com/test.pem';

    public function testAuthenticatesOnlyUntamperedMessagesFromAllowedTopic(): void
    {
        $key       = openssl_pkey_new(['private_key_bits' => 2048]);
        $publicKey = openssl_pkey_get_details($key)['key'];
        $validator = new MessageValidator(static fn (string $url): string => $publicKey);
        $payload   = $this->signedPayload($key);
        $subject   = new SnsWebhookAuthenticator();

        self::assertNull($subject->rejectionReason($payload, [self::TOPIC], $validator));

        $tampered            = $payload;
        $tampered['Message'] = '{"notificationType":"Complaint"}';
        self::assertSame('The message signature is invalid.', $subject->rejectionReason($tampered, [self::TOPIC], $validator));
        self::assertSame('The TopicArn is not an allowed topic.', $subject->rejectionReason($payload, [self::TOPIC.'-other'], $validator));
        self::assertNotNull($subject->rejectionReason(['eventType' => 'Bounce'], [self::TOPIC], $validator));
    }

    public function testDownloadsTheCertificateOnceWithinTheTimeout(): void
    {
        $key      = openssl_pkey_new(['private_key_bits' => 2048]);
        $requests = [];
        $client   = new MockHttpClient(static function (string $method, string $url, array $options) use ($key, &$requests): MockResponse {
            $requests[] = [$method, $url, $options['timeout'], $options['max_duration']];

            return new MockResponse(openssl_pkey_get_details($key)['key']);
        });
        $subject = new SnsWebhookAuthenticator($client, new ArrayAdapter());
        $payload = $this->signedPayload($key);

        self::assertNull($subject->rejectionReason($payload, [self::TOPIC]));
        self::assertNull($subject->rejectionReason($payload, [self::TOPIC]));
        $tampered            = $payload;
        $tampered['Message'] = '{"notificationType":"Complaint"}';
        self::assertSame('The message signature is invalid.', $subject->rejectionReason($tampered, [self::TOPIC]));

        self::assertSame([['GET', self::CERTIFICATE_URL, 5.0, 5.0]], $requests);
    }

    /**
     * @dataProvider failedDownloads
     */
    public function testFailedCertificateDownloadIsNotARejection(MockResponse $response): void
    {
        $key       = openssl_pkey_new(['private_key_bits' => 2048]);
        $responses = [$response, new MockResponse(openssl_pkey_get_details($key)['key'])];
        $subject   = new SnsWebhookAuthenticator(new MockHttpClient($responses), new ArrayAdapter());
        $payload   = $this->signedPayload($key);

        try {
            $subject->rejectionReason($payload, [self::TOPIC]);
            self::fail('A failed download must not decide authenticity.');
        } catch (SnsCertificateUnavailable $e) {
            self::assertStringContainsString(self::CERTIFICATE_URL, $e->getMessage());
        }
        // Nothing was cached, so SNS's next attempt downloads the certificate again.
        self::assertNull($subject->rejectionReason($payload, [self::TOPIC]));
    }

    public static function failedDownloads(): array
    {
        return [
            'network error'     => [new MockResponse('', ['error' => 'Could not resolve host: sns.eu-west-1.amazonaws.com'])],
            'server error'      => [new MockResponse('Service Unavailable', ['http_code' => 503])],
            'not a certificate' => [new MockResponse('<html>Access denied by proxy</html>')],
        ];
    }

    /** @return array<string, string> */
    private function signedPayload(\OpenSSLAsymmetricKey $key): array
    {
        $payload = [
            'Type'              => 'Notification',
            'Message'           => '{"notificationType":"Bounce"}',
            'MessageId'         => 'unit-test',
            'Timestamp'         => '2026-09-20T00:00:00Z',
            'TopicArn'          => self::TOPIC,
            'SignatureVersion'  => '2',
            'Signature'         => '',
            'SigningCertURL'    => self::CERTIFICATE_URL,
        ];
        openssl_sign(
            (new MessageValidator())->getStringToSign(new Message($payload)),
            $signature,
            $key,
            OPENSSL_ALGO_SHA256,
        );
        $payload['Signature'] = base64_encode($signature);

        return $payload;
    }
}
