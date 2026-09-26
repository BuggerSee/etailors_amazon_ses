<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Helper;

use Aws\Sns\Message;
use Aws\Sns\MessageValidator;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class SnsWebhookAuthenticator
{
    /** Seconds for downloading a signing certificate; SNS waits 15 seconds for the answer to a notification. */
    private const CERTIFICATE_TIMEOUT = 5;
    /** Seconds a downloaded certificate is reused. SNS publishes a new signing certificate under a new URL. */
    private const CERTIFICATE_TTL = 3600;

    public function __construct(
        private ?HttpClientInterface $httpClient = null,
        private ?CacheInterface $cache = null,
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     * @param list<string>         $allowedTopicArns
     *
     * @return string|null why the message is rejected, or null when it is authentic
     *
     * @throws SnsCertificateUnavailable when the signing certificate cannot be downloaded, so authenticity is undecided
     */
    public function rejectionReason(
        array $payload,
        array $allowedTopicArns,
        ?MessageValidator $validator = null,
    ): ?string {
        $topicArn = (string) ($payload['TopicArn'] ?? '');
        $allowed  = array_filter(
            $allowedTopicArns,
            static fn (string $candidate): bool => hash_equals($candidate, $topicArn),
        );

        if ('' === $topicArn || [] === $allowed) {
            return 'The TopicArn is not an allowed topic.';
        }

        if (!in_array($payload['Type'] ?? null, ['Notification', 'SubscriptionConfirmation'], true)) {
            return 'The message type is not supported.';
        }

        try {
            $message = new Message($payload);
            ($validator ?? new MessageValidator($this->certificate(...)))->validate($message);

            return null;
        } catch (SnsCertificateUnavailable $e) {
            throw $e;
        } catch (\Throwable $e) {
            return $e->getMessage();
        }
    }

    /**
     * Called by the validator only for an HTTPS URL on an SNS host.
     *
     * @throws SnsCertificateUnavailable
     */
    private function certificate(string $url): string
    {
        $download = function () use ($url): string {
            try {
                $pem = ($this->httpClient ??= HttpClient::create())
                    ->request('GET', $url, ['timeout' => self::CERTIFICATE_TIMEOUT, 'max_duration' => self::CERTIFICATE_TIMEOUT])
                    ->getContent();
            } catch (ExceptionInterface $e) {
                throw new SnsCertificateUnavailable(sprintf('Cannot download the SNS signing certificate from "%s": %s', $url, $e->getMessage()), 0, $e);
            }
            // Something other than a certificate (a proxy's error page, a truncated body) is neither cached nor a bad signature.
            if (false === openssl_pkey_get_public($pem)) {
                throw new SnsCertificateUnavailable(sprintf('The response from "%s" holds no public key.', $url));
            }

            return $pem;
        };

        if (null === $this->cache) {
            return $download();
        }

        // A failed download throws before anything is stored, so the next notification tries again.
        return $this->cache->get('amazon_ses_sns_certificate.'.hash('sha256', $url), static function (ItemInterface $item) use ($download): string {
            $item->expiresAfter(self::CERTIFICATE_TTL);

            return $download();
        });
    }
}
