<?php

declare(strict_types=1);

/*
 * Router script for PHP's built-in web server, no Composer autoloader needed:
 *
 *   FAKE_SES_RATE=80 FAKE_SES_LOG=/tmp/fake-ses-requests.jsonl php -S 127.0.0.1:4566 Tests/E2E/fake-ses-server.php
 *
 * Point the plugin at it with the DSN option endpoint=http%3A%2F%2F127.0.0.1%3A4566.
 */

use MauticPlugin\AmazonSesBundle\Tests\E2E\FakeSesServer;

require_once __DIR__.'/FakeSesServer.php';

$server   = new FakeSesServer((int) (getenv('FAKE_SES_RATE') ?: 80), getenv('FAKE_SES_LOG') ?: sys_get_temp_dir().'/fake-ses-requests.jsonl');
$response = $server->handle($_SERVER['REQUEST_METHOD'], (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), (string) file_get_contents('php://input'));

http_response_code($response['status']);
foreach ($response['headers'] as $name => $value) {
    header($name.': '.$value);
}
echo $response['body'];
