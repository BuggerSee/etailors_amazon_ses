<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Mautic\IntegrationsBundle\Migration\AbstractMigration;
use MauticPlugin\AmazonSesBundle\Mailer\Bulk\DeliveryStore;

/** Mautic creates plugin tables from entity metadata only on first install; existing installs get the SES bulk outbox here. */
final class Version_1_0_42 extends AbstractMigration
{
    protected function isApplicable(Schema $schema): bool
    {
        return !$schema->hasTable($this->concatPrefix('ses_bulk_contents'))
            || !$schema->hasTable($this->concatPrefix('ses_bulk_deliveries'));
    }

    protected function up(): void
    {
        foreach (DeliveryStore::createSchemaSql($this->entityManager) as $sql) {
            $this->addSql($sql);
        }
    }
}
