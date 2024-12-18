# Hash Sensitive

Monolog processor to protect sensitive information from logging by hashing the values.

[![Packagist Version](https://img.shields.io/packagist/v/globyapp/hash-sensitive)](https://packagist.org/packages/globyapp/hash-sensitive) [![Packagist](https://img.shields.io/packagist/l/globyapp/hash-sensitive)](https://github.com/globyapp/hash-sensitive/blob/master/LICENSE) [![PHP from Packagist](https://img.shields.io/packagist/php-v/globyapp/hash-sensitive)](https://github.com/globyapp/hash-sensitive/blob/master/composer.json#L14) [![CI](https://github.com/Globy-App/hash-sensitive/actions/workflows/ci.yml/badge.svg)](https://github.com/Globy-App/hash-sensitive/actions/workflows/ci.yml)

## Summary

- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Examples](#examples)
- [API](#api)
- [Known issues](#known-issues)
- [Thanks](#thanks)

## About

A Monolog processor that protects sensitive data from miss logging. Forked from: [redact-sensitive](https://github.com/leocavalcante/redact-sensitive) by [Leo Cavalcante](https://github.com/leocavalcante).
When redacting values from logs, it might be useful to be able to compare redacted values that are equal.

Avoids logging something like `{"api_key":"mysupersecretapikey"}` by substituting the value by a hashed version of the value:
```text
Readme.INFO: Hello, World! {"api_key":"3f6b5eb5b4bc422fc119c76caccd8792d1cf253a71a04d520206a01f1463ca41"} []
```

## Features

- Adds a monolog processor to hash pre-determined array keys.
- Hashes sensitive data in the monolog context to prevent sending secrets to the logs.
- The hashed version is deterministic and thus allows for correlation between errors.

## Requirements

- PHP >= 8.1.0
- [Composer](https://getcomposer.org/)
- Monolog >= 3.0

## Installation

Add the package to your dependencies:

```bash
composer require globyapp/hash-sensitive
```

### Usage

#### 1. Prepare your sensitive keys

It is an array of key names, for example:
```php
$sensitive_keys = ['api_key'];
```
Will hash the value of the `api_key`. Because of PHP's tendency to automatically add integer indexes to such an array,
integers in sensitive keys will be ignored and might lead to unexpected results. To be on the safe side, only use
sensitive string keys, or a nested tree of strings.

#### 2. Create a Processor using the keys

You can now create a new Processor with the given keys:

```php
use GlobyApp\HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key'];

$processor = new HashSensitiveProcessor($sensitive_keys);
```

#### 3. Set the Processor to a Monolog\Logger

```php
use GlobyApp\HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key'];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Readme');
$logger->pushProcessor($processor);
```

## Examples

```php
use Monolog\Handler\StreamHandler;
use GlobyApp\HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key'];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Readme', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Hello, World!', ['api_key' => 'mysupersecretapikey']);
```
```text
Readme.INFO: Hello, World! {"api_key":"3f6b5eb5b4bc422fc119c76caccd8792d1cf253a71a04d520206a01f1463ca41"} []
```

### Using the library standalone

It is possible to use the logic in the library without using it as a monolog hook. This can be achieved by constructing a new instance of the `Hasher` class.
function `scrubKeys`, an array of values to scrub and the sensitive key array can be specified in the same manner as when using the library with monolog.

### I don't want my output to be hashed, just replaced with a pre-determined string
If you're looking for formating the output with a user defined string, this isn't the right project.
You might want to look into [redact-sensitive](https://github.com/leocavalcante/redact-sensitive).

## API
### Length limit & algorithm

Use `lengthLimit` to truncate redacted sensitive information, such as lengthy tokens. Truncation always happens before hashing.
Use `algorithm` to specify the algorithm used for hashing the value. Refer to [the php documentation](https://www.php.net/manual/en/function.hash-algos.php) for a list of supported algorithms.

```php
use Monolog\Handler\StreamHandler;
use GlobyApp\HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['access_token'];

$processor = new HashSensitiveProcessor($sensitive_keys, algorithm: 'sha256', lengthLimit: 5);

$logger = new \Monolog\Logger('Example', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Truncated secret', ['access_token' => 'Very long JWT ...']);
$logger->info('Truncated secret', ['access_token' => 'Very long token ...']);
```
```text
Example.INFO: Truncated secret {"access_token":"22e25a68c0ef48364f3f12a0ebbb550e595e15aaec09a96ca3eea7d78daa2b72"} []
Example.INFO: Truncated secret {"access_token":"22e25a68c0ef48364f3f12a0ebbb550e595e15aaec09a96ca3eea7d78daa2b72"} []
```

### Nested values

It should work with nested objects and arrays as well. For more granular control over how nested values are handled,
the `exclusiveSubtree` boolean can set. When set to true, this causes the algorithm to, if there is a subtree specified
in the sensitive keys, only check the subtree in the values against keys in that subtree of the sensitive keys.
This is the default behavior.
When set to false, every key in the input data is checked against every key in sensitive keys.

```php
use Monolog\Handler\StreamHandler;
use GlobyApp\HashSensitive\HashSensitiveProcessor;

$sensitive_keys = [
    'test',
    'test_subkey' => [
        'to_hash',
    ], 
];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Example', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Nested', [
    'test_key' => 'test_value',
    'test_subkey' => [
        'to_hash' => 'test_value',
        'test' => 'test',
    ],
]);
```
`exclusiveSubtree = true:` (`test` is not hashed, because `test_subkey` specifies a subkey configuration in `$sensitive_keys` in which only `to_hash` is hashed).
```text
Example.INFO: Nested {"test_key":"test_value","test_subkey":{"to_hash":"4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006","test":"test"}} []
```
`exclusiveSubtree = false:` (`test` is hashed, because `test` is a key in `$sensitive_keys`).
```text
Example.INFO: Nested {"test_key":"test_value","test_subkey":{"to_hash":"4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006","test":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}} []
```

## Known issues

Currently, there are no known issues.

## Thanks
Feel free to open any issues or PRs.

---
MIT &copy; 2024
