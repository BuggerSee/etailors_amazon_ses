<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Mailer\Bulk;

use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Mautic\EmailBundle\Entity\Stat;
use MauticPlugin\AmazonSesBundle\Entity\BulkContent;
use MauticPlugin\AmazonSesBundle\Entity\BulkDelivery;

final class DeliveryStore
{
    private string $deliveries;
    private string $contents;
    private bool $ready = false;
    /** @var array<string, true> content ids this instance inserted or found present */
    private array $contentIds = [];

    public function __construct(private EntityManagerInterface $entityManager)
    {
        $this->deliveries = $entityManager->getClassMetadata(BulkDelivery::class)->getTableName();
        $this->contents = $entityManager->getClassMetadata(BulkContent::class)->getTableName();
    }

    /**
     * Shared by install() and the plugin migration.
     *
     * @return string[] CREATE statements for whichever outbox tables do not exist yet
     */
    public static function createSchemaSql(EntityManagerInterface $entityManager): array
    {
        $manager = $entityManager->getConnection()->createSchemaManager();
        $missing = [];
        foreach ([BulkContent::class, BulkDelivery::class] as $class) {
            $metadata = $entityManager->getClassMetadata($class);
            if (!$manager->tablesExist([$metadata->getTableName()])) {
                $missing[] = $metadata;
            }
        }

        return $missing ? (new SchemaTool($entityManager))->getCreateSchemaSql($missing) : [];
    }

    public function install(): void
    {
        $db = $this->entityManager->getConnection();
        foreach (self::createSchemaSql($this->entityManager) as $sql) {
            $db->executeStatement($sql);
        }
        $this->ready = true;
    }

    public function assertInstalled(): void
    {
        if (!$this->ready && !$this->entityManager->getConnection()->createSchemaManager()->tablesExist([$this->contents, $this->deliveries])) {
            throw new \RuntimeException('SES bulk tables are missing. Run bin/console mautic:ses:bulk install before enabling bulk=auto.');
        }
        $this->ready = true;
    }

    /** Save before submission. Existing deliveries are deliberately immutable on queue replay. */
    public function enqueue(array $delivery, string $scope): string
    {
        $this->assertInstalled();
        $db = $this->entityManager->getConnection();
        $now = time();
        $contentId = hash('sha256', serialize([$scope, $delivery['operation'], $delivery['email_id'], $delivery['common']]));
        // Recipients of one message share content: insert it once per instance instead of failing once per recipient.
        if (!isset($this->contentIds[$contentId])) {
            try {
                $db->insert($this->contents, [
                    'id' => $contentId, 'email_id' => $delivery['email_id'], 'scope' => $scope,
                    'operation' => $delivery['operation'], 'payload' => json_encode($delivery['common'], JSON_THROW_ON_ERROR),
                    'requests' => 0, 'request_bytes' => 0, 'created_at' => $now,
                ]);
            } catch (UniqueConstraintViolationException) {
                // Common content is shared across recipients and workers.
            }
            $this->contentIds[$contentId] = true;
        }
        try {
            $db->insert($this->deliveries, [
                'id' => $delivery['id'], 'content_id' => $contentId, 'email_id' => $delivery['email_id'],
                'tracking_hash' => $delivery['tracking_hash'], 'scope' => $scope,
                'entry' => json_encode($delivery['entry'], JSON_THROW_ON_ERROR), 'state' => 'pending',
                'event' => '', 'reason' => $delivery['reason'], 'message_id' => '', 'attempts' => 0,
                'next_attempt' => 0, 'updated_at' => $now, 'created_at' => $now, 'claim' => '', 'synced' => 0,
            ]);
        } catch (UniqueConstraintViolationException) {
            // A second worker/re-delivered Messenger job must not reset the first outcome.
        }

        return $delivery['id'];
    }

    /** Atomic ownership prevents two workers submitting the same delivery. */
    public function claim(string $id, string $scope, string $owner): ?array
    {
        $db = $this->entityManager->getConnection();
        $changed = $db->executeStatement(
            "UPDATE {$this->deliveries} SET state = 'sending', claim = ?, attempts = attempts + 1, updated_at = ? WHERE id = ? AND scope = ? AND state IN ('pending', 'retry') AND next_attempt <= ? AND attempts < 4",
            [$owner, time(), $id, $scope, time()]
        );
        if (!$changed) {
            return null;
        }

        return $db->fetchAssociative("SELECT * FROM {$this->deliveries} WHERE id = ?", [$id]) ?: null;
    }

    public function complete(array $row, string $state, string $reason = '', string $messageId = ''): void
    {
        if ('retry' === $state && (int) $row['attempts'] >= 4) {
            $state = 'rejected';
            $reason = 'retry_exhausted:'.$reason;
        }
        // Accepted on a retry drops the earlier attempt's failure reason. Before the first attempt the reason can only be
        // the raw-fallback reason from enqueue(), which stays.
        $this->entityManager->getConnection()->executeStatement(
            "UPDATE {$this->deliveries} SET state = ?, reason = CASE WHEN ? = 'accepted' AND attempts > 1 THEN '' WHEN ? = '' THEN reason ELSE ? END, message_id = CASE WHEN ? = '' THEN message_id ELSE ? END, next_attempt = ?, updated_at = ?, synced = 0 WHERE id = ? AND claim = ? AND state = 'sending'",
            [$state, $state, $reason, substr($reason, 0, 128), $messageId, $messageId, time() + min(3600, 30 * (2 ** (int) $row['attempts'])), time(), $row['id'], $row['claim']]
        );
    }

    public function recordRequest(string $contentId, int $bytes): void
    {
        $this->entityManager->getConnection()->executeStatement(
            "UPDATE {$this->contents} SET requests = requests + 1, request_bytes = request_bytes + ? WHERE id = ?", [$bytes, $contentId]
        );
    }

    public function content(string $id): array
    {
        $row = $this->entityManager->getConnection()->fetchAssociative("SELECT * FROM {$this->contents} WHERE id = ?", [$id]);
        if (!$row) {
            throw new \RuntimeException('Missing persisted SES content.');
        }
        $row['payload'] = json_decode($row['payload'], true, 512, JSON_THROW_ON_ERROR);

        return $row;
    }

    public function due(string $scope, int $limit): array
    {
        $limit = max(1, min(10000, $limit));

        return $this->entityManager->getConnection()->fetchAllAssociative(
            "SELECT * FROM {$this->deliveries} WHERE scope = ? AND state IN ('pending', 'retry') AND next_attempt <= ? AND attempts < 4 ORDER BY content_id, created_at, id LIMIT {$limit}", [$scope, time()]
        );
    }

    /** Expired claims mean unknown acceptance, never permission to resend. */
    public function expireClaims(string $scope): int
    {
        return $this->entityManager->getConnection()->executeStatement(
            "UPDATE {$this->deliveries} SET state = 'unknown', reason = 'worker_interrupted', updated_at = ? WHERE scope = ? AND state = 'sending' AND updated_at < ?", [time(), $scope, time() - 600]
        );
    }

    /** Called only after SNS signature/topic authentication by CallbackSubscriber. */
    public function recordEvent(array $payload, string $type): void
    {
        $event = ['Send' => 'sent', 'Delivery' => 'delivered', 'Bounce' => 'bounced', 'Complaint' => 'complained', 'Rendering Failure' => 'rendering_failed', 'Reject' => 'rejected'][$type] ?? null;
        if (null === $event) {
            return;
        }
        $id = $payload['mail']['tags']['mautic_delivery_id'][0] ?? '';
        if (!is_string($id) || !preg_match('/^[a-f0-9]{64}$/D', $id)) {
            return;
        }
        $this->assertInstalled();
        // Events can arrive before the HTTP response. Do not overwrite a later terminal event with Send/Delivery.
        $db = $this->entityManager->getConnection();
        $row = $db->fetchAssociative("SELECT * FROM {$this->deliveries} WHERE id = ?", [$id]);
        if (!$row) {
            return;
        }
        $rank = ['' => 0, 'sent' => 1, 'delivered' => 2, 'bounced' => 3, 'rendering_failed' => 3, 'rejected' => 3, 'complained' => 4];
        if (($rank[$row['event']] ?? 0) > $rank[$event]) {
            return;
        }
        $db->executeStatement(
            "UPDATE {$this->deliveries} SET state = 'accepted', event = ?, message_id = ?, updated_at = ?, synced = 0 WHERE id = ? AND event = ?",
            [$event, (string) ($payload['mail']['messageId'] ?? $row['message_id']), time(), $id, $row['event']]
        );
    }

    public function summary(?int $emailId = null): array
    {
        $this->assertInstalled();
        $db = $this->entityManager->getConnection();
        $where = null === $emailId ? '' : ' WHERE d.email_id = ?';
        $args = null === $emailId ? [] : [$emailId];
        $recipients = $db->fetchAllAssociative("SELECT c.operation, d.state, d.event, d.reason, COUNT(*) AS recipients, SUM(d.attempts) AS attempts FROM {$this->deliveries} d INNER JOIN {$this->contents} c ON c.id = d.content_id{$where} GROUP BY c.operation, d.state, d.event, d.reason", $args);
        $where = null === $emailId ? '' : ' WHERE email_id = ?';
        $requests = $db->fetchAllAssociative("SELECT operation, SUM(requests) AS requests, SUM(request_bytes) AS request_bytes FROM {$this->contents}{$where} GROUP BY operation", $args);

        return ['email_id' => $emailId, 'recipients' => $recipients, 'requests' => $requests];
    }

    /** Reconcile after Mautic inserts its statistics, without adding a DNC/bounce for transport errors. */
    public function syncFailures(int $limit = 1000): int
    {
        $limit = max(1, min(10000, $limit));
        $db = $this->entityManager->getConnection();
        $table = $this->entityManager->getClassMetadata(Stat::class)->getTableName();
        $rows = $db->fetchAllAssociative("SELECT id, tracking_hash, email_id FROM {$this->deliveries} WHERE synced = 0 AND (state = 'rejected' OR event IN ('rendering_failed', 'rejected', 'bounced')) ORDER BY updated_at LIMIT {$limit}");
        $count = 0;
        foreach ($rows as $row) {
            // Stats may not exist yet (synchronous sending); leave the row pending reconciliation.
            if (!$db->fetchOne("SELECT id FROM {$table} WHERE tracking_hash = ? AND email_id = ?", [$row['tracking_hash'], $row['email_id']])) {
                continue;
            }
            $db->executeStatement("UPDATE {$table} SET is_failed = 1 WHERE tracking_hash = ? AND email_id = ?", [$row['tracking_hash'], $row['email_id']]);
            $db->update($this->deliveries, ['synced' => 1], ['id' => $row['id']]);
            ++$count;
        }

        return $count;
    }
}
