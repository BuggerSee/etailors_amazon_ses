<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Mailer\Bulk;

use Aws\Exception\AwsException;
use Aws\SesV2\SesV2Client;
use Psr\Log\LoggerInterface;

final class BulkSender
{
    public function __construct(private DeliveryStore $store, private LoggerInterface $logger)
    {
    }

    public static function scope(SesV2Client $client): string
    {
        return hash('sha256', $client->getRegion().'|'.$client->getCredentials()->wait()->getAccessKeyId());
    }

    public static function assertSupported(SesV2Client $client): void
    {
        $input = $client->getApi()->getOperation('SendBulkEmail')->getInput();
        if (!$input->getMember('DefaultContent')->getMember('Template')->hasMember('TemplateContent') || !$input->getMember('BulkEmailEntries')->getMember()->hasMember('ReplacementHeaders')) {
            throw new \RuntimeException('The installed AWS SDK lacks SES inline templates/replacement headers. Update aws/aws-sdk-php before enabling bulk=auto.');
        }
    }

    /** @param callable(int): void $acquire */
    public function send(SesV2Client $client, array $ids, callable $acquire): void
    {
        $scope = self::scope($client);
        $owner = bin2hex(random_bytes(16));
        $groups = [];
        foreach ($ids as $id) {
            if ($row = $this->store->claim($id, $scope, $owner)) {
                $groups[$row['content_id']][] = $row;
            }
        }
        foreach ($groups as $contentId => $rows) {
            $content = $this->store->content($contentId);
            $entries = array_map(static fn (array $row): array => json_decode($row['entry'], true, 512, JSON_THROW_ON_ERROR), $rows);
            if ('bulk' === $content['operation']) {
                $request = BulkBatcher::request($content['payload'], $entries);
                $operation = 'SendBulkEmail';
                $recipients = count($entries);
            } else {
                $request = $content['payload'];
                $request['Content']['Raw']['Data'] = base64_decode($request['Content']['Raw']['Data'], true);
                $operation = 'SendEmail';
                $recipients = array_sum(array_map('count', $request['Destination']));
            }
            try {
                $acquire($recipients);
                $this->store->recordRequest($contentId, BulkBatcher::bytes($request));
            } catch (\Throwable $e) {
                // Nothing has been submitted; releasing the claim for a later retry is safe.
                foreach ($rows as $row) {
                    $this->store->complete($row, 'retry', 'local_preflight_failure');
                }
                throw $e;
            }
            try {
                // Disable hidden whole-request retries. Outcome handling belongs to this ledger.
                $command = $client->getCommand($operation, $request + [
                    '@retries' => 0,
                    '@http' => ['connect_timeout' => 10, 'timeout' => 60],
                ]);
                $result = $client->execute($command);
            } catch (\InvalidArgumentException $e) {
                // SDK input validation failed before dispatch.
                foreach ($rows as $row) {
                    $this->store->complete($row, 'rejected', 'sdk_validation');
                }
                $this->logger->error('SES bulk SDK validation failed.', ['exception' => $e]);
                continue;
            } catch (\Throwable $e) {
                [$state, $reason] = $this->exceptionOutcome($e);
                foreach ($rows as $row) {
                    $this->store->complete($row, $state, $reason);
                }
                $this->logger->warning('SES request did not return recipient results.', ['state' => $state, 'reason' => $reason, 'recipients' => count($rows)]);
                continue;
            }
            if ('raw' === $content['operation']) {
                $messageId = (string) ($result['MessageId'] ?? '');
                $this->store->complete($rows[0], $messageId ? 'accepted' : 'unknown', $messageId ? '' : 'missing_result', $messageId);
                continue;
            }
            $results = $result['BulkEmailEntryResults'] ?? [];
            // Positional results cannot safely be mapped if the count differs.
            if (!is_array($results) || count($results) !== count($rows)) {
                foreach ($rows as $row) {
                    $this->store->complete($row, 'unknown', 'invalid_result_count');
                }
                continue;
            }
            foreach ($rows as $i => $row) {
                $entry = $results[$i] ?? [];
                $status = $entry['Status'] ?? '';
                $messageId = (string) ($entry['MessageId'] ?? '');
                if ('SUCCESS' === $status && '' !== $messageId) {
                    $this->store->complete($row, 'accepted', '', $messageId);
                } elseif (in_array($status, ['ACCOUNT_THROTTLED', 'ACCOUNT_DAILY_QUOTA_EXCEEDED', 'TRANSIENT_FAILURE', 'FAILED'], true)) {
                    $this->store->complete($row, 'retry', $status);
                } elseif (in_array($status, ['MESSAGE_REJECTED', 'MAIL_FROM_DOMAIN_NOT_VERIFIED', 'CONFIGURATION_SET_NOT_FOUND', 'CONFIGURATION_SET_DOES_NOT_EXIST', 'TEMPLATE_NOT_FOUND', 'TEMPLATE_DOES_NOT_EXIST', 'ACCOUNT_SUSPENDED', 'INVALID_SENDING_POOL_NAME', 'ACCOUNT_SENDING_PAUSED', 'CONFIGURATION_SET_SENDING_PAUSED', 'INVALID_PARAMETER', 'INVALID_PARAMETER_VALUE'], true)) {
                    $this->store->complete($row, 'rejected', $status);
                } else {
                    $this->store->complete($row, 'unknown', 'unrecognized_result');
                }
            }
            $this->logger->info('SES shared-template request processed.', ['email_id' => $content['email_id'], 'recipients' => count($rows), 'content_id' => $contentId]);
        }
    }

    private function exceptionOutcome(\Throwable $e): array
    {
        if ($e instanceof AwsException) {
            $code = (string) $e->getAwsErrorCode();
            if (in_array($code, ['TooManyRequestsException', 'Throttling', 'ThrottlingException', 'LimitExceededException'], true)) {
                return ['retry', $code];
            }
            if (in_array($code, ['BadRequestException', 'MessageRejected', 'MailFromDomainNotVerifiedException', 'NotFoundException', 'AccountSuspendedException', 'SendingPausedException', 'AccessDeniedException', 'UnrecognizedClientException', 'InvalidSignatureException'], true)) {
                return ['rejected', $code];
            }
        }

        // Timeouts, broken connections and 5xx responses can follow acceptance.
        return ['unknown', 'ambiguous_request_failure'];
    }
}
