<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use GlobyApp\HashSensitive\Hasher;

it('redacts nested objects', function (): void {
    $nested = new \stdClass();
    $nested->value = 'foobar';
    $nested->nested = ['value' => 'bazqux'];

    $input = ['test' => ['nested' => $nested]];
    $sensitive_keys = ['test' => ['nested' => ['value', 'nested' => ['value']]]];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['test' => ['nested' => $nested]])
        ->and($nested->value)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($nested->nested['value'])->toBe('972c5e1203896784a7cf9dd60acd443a1065e19ad5f92e59a9180c185f065c04');
});

it('works without sensitive key subobjects', function (): void {
    $nested = new \stdClass();
    $nested->foobar = "test";

    $obj = new \stdClass();
    $obj->test = $nested;

    $input = ['obj' => $obj];
    $sensitive_keys = ['test'];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['obj' => $obj])
        ->and($obj->test)->toBe('914dba76d2c953789b8ec73425b85bea1c8298815dd0afc1e4fc6c2d8be69648');
});

it('keeps non redacted nested objects intact', function (): void {
    $nested = new \stdClass();
    $nested->value = 'bazqux';
    $nested->no_hash = 'foobar';

    $value = new \stdClass();
    $value->value = 'foobar';
    $value->nested = $nested;

    $input = ['test' => ['nested' => $value]];
    $sensitive_keys = ['test' => ['nested' => ['value', 'nested' => ['value']]]];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['test' => ['nested' => $value]])
        ->and($value->value)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($value->nested)->toBe($nested)
        ->and($nested->value)->toBe('972c5e1203896784a7cf9dd60acd443a1065e19ad5f92e59a9180c185f065c04')
        ->and($nested->no_hash)->toBe('foobar');
});

it('doesn\'t break on null values in input object', function (): void {
    $nested = new \stdClass();
    $nested->value = null;
    $nested->no_hash = null;

    $value = new \stdClass();
    $value->value = 'foobar';
    $value->nested = $nested;

    $input = ['test' => ['nested' => $value]];
    $sensitive_keys = ['test' => ['nested' => ['value', 'nested' => ['value']]]];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['test' => ['nested' => $value]])
        ->and($value->value)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($value->nested)->toBe($nested)
        ->and($nested->value)->toBeNull()
        ->and($nested->no_hash)->toBeNull();
});

it('doesn\'t break on null values in sensitive keys (object)', function (): void {
    $nested = new \stdClass();
    $nested->value = 'foobar';
    $nested->nested = ['value' => 'bazqux', 'no_hash' => 'foobar'];

    $input = ['test' => ['nested' => $nested]];
    $sensitive_keys = ['test' => ['nested' => [null, 'nested' => [null], null], null], null];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['test' => ['nested' => $nested]])
        ->and($nested->nested['no_hash'])->toBe('foobar');
});

it('redacts inside nested objects', function (): void {
    $nested = new \stdClass();
    $nested->value = 'foobar';
    $nested->nested = ['value' => 'bazqux'];

    $input = ['test' => ['nested' => $nested]];
    $sensitive_keys = ['nested' => ['value']];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['test' => ['nested' => $nested]])
        ->and($nested->value)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($nested->nested['value'])->toBe('972c5e1203896784a7cf9dd60acd443a1065e19ad5f92e59a9180c185f065c04');
});

it('it hashes all instances with exclusiveSubtree false in nested objects', function (): void {
    $nested = new \stdClass();
    $nested->to_hash = 'test_value';
    $nested->test = 'test';

    $value = new \stdClass();
    $value->test_key = 'test_value';
    $value->test_subkey = $nested;

    $input = ['nested' => $value];
    $sensitive_keys = ['test', 'test_subkey' => ['to_hash']];

    $processor = new Hasher('sha256', null, false);
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['nested' => $value])
        ->and($value->test_key)->toBe('test_value')
        ->and($value->test_subkey)->toBe($nested)
        ->and($nested->to_hash)->toBe('4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006')
        ->and($nested->test)->toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
});

it('ensures exclusiveSubtree is turned on by default for objects', function (): void {
    $nested = new \stdClass();
    $nested->to_hash = 'test_value';
    $nested->test = 'test';

    $value = new \stdClass();
    $value->test_key = 'test_value';
    $value->test_subkey = $nested;

    $input = ['nested' => $value];
    $sensitive_keys = ['test', 'test_subkey' => ['to_hash']];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['nested' => $value])
        ->and($value->test_key)->toBe('test_value')
        ->and($value->test_subkey)->toBe($nested)
        ->and($nested->to_hash)->toBe('4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006')
        ->and($nested->test)->toBe('test');
});

it('preserves empty values in objects', function (): void {
    $nested = new \stdClass();
    $nested->test = 'foobar';
    $nested->optionalKey = '';

    $input = ['nested' => $nested];
    $sensitive_keys = ['test', 'optionalKey'];

    $processor = new Hasher();
    $result = $processor->scrubKeys($input, $sensitive_keys);

    expect($result)->toBe(['nested' => $nested])
        ->and($nested->test)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($nested->optionalKey)->toBeNull();
});