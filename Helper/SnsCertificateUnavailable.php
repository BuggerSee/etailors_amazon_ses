<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Helper;

/** The SNS signing certificate could not be downloaded, so whether a message is authentic is still undecided. */
final class SnsCertificateUnavailable extends \RuntimeException
{
}
