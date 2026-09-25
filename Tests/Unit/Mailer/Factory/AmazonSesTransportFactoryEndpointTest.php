<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Tests\Unit\Mailer\Factory;

use Doctrine\ORM\EntityManagerInterface;
use Mautic\CoreBundle\Helper\PathsHelper;
use Mautic\EmailBundle\Model\EmailStatModel;
use Mautic\EmailBundle\Model\TransportCallback;
use Mautic\EmailBundle\MonitoredEmail\Search\ContactFinder;
use Mautic\LeadBundle\Model\DoNotContact;
use MauticPlugin\AmazonSesBundle\Mailer\Factory\AmazonSesTransportFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Mailer\Exception\InvalidArgumentException;
use Symfony\Component\Mailer\Transport\Dsn;
use Symfony\Contracts\Translation\TranslatorInterface;

class AmazonSesTransportFactoryEndpointTest extends TestCase
{
    public function testEndpointOptionOverridesRegionalEndpoint(): void
    {
        $client = $this->factory()->initAmazonClient(Dsn::fromString('mautic+ses+api://key:secret@default?region=eu-central-1&endpoint=http%3A%2F%2F127.0.0.1%3A4566'));

        self::assertSame('http://127.0.0.1:4566', (string) $client->getEndpoint());
    }

    /**
     * @dataProvider invalidEndpoints
     */
    public function testInvalidEndpointIsRejected(string $endpoint): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SES endpoint must be an absolute http(s) URL.');

        $this->factory()->initAmazonClient(Dsn::fromString('mautic+ses+api://key:secret@default?region=eu-central-1&endpoint='.$endpoint));
    }

    public static function invalidEndpoints(): array
    {
        return [
            'non-http scheme' => ['ftp%3A%2F%2Fx'],
            'not a url'       => ['not-a-url'],
        ];
    }

    private function factory(): AmazonSesTransportFactory
    {
        // TransportCallback is final in Mautic 7, so it is built from mocked collaborators instead of mocked itself.
        $callback = new TransportCallback($this->createMock(DoNotContact::class), $this->createMock(ContactFinder::class), $this->createMock(EmailStatModel::class));

        return new AmazonSesTransportFactory(
            $callback,
            $this->createMock(EventDispatcherInterface::class),
            $this->createMock(TranslatorInterface::class),
            $this->createMock(EntityManagerInterface::class),
            $this->createMock(PathsHelper::class),
        );
    }
}
