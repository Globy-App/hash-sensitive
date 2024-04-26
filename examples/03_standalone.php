<?php declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use GlobyApp\HashSensitive\Hasher;

$sensitive_keys = ['api_key'];

$hasher = new Hasher();
var_dump($hasher->scrubKeys(['api_key' => 'mysupersecretapikey'], $sensitive_keys));
