<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use GlobyApp\HashSensitive\Hasher;
use GlobyApp\HashSensitive\HashSensitiveProcessor;
use TypeError;

it('redacts records contexts', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->simpleExample->getInput(), $this->simpleExample->getSensitiveKeys());

    expect($result)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('works without sensitive key subtrees', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->nestedExample->getInput(), $this->nestedExample->getSensitiveKeys());

    expect($result)->toBe(['test' => 'c413de2c94a3a668b82ae2207da4b6961eeeccaff97623e2143d978610cb4746']);
});

it('truncates masked characters', function (): void {
    $processor = new Hasher('sha256', 5);
    $result = $processor->scrubKeys($this->simpleExample->getInput(), $this->simpleExample->getSensitiveKeys());

    // Only `fooba` should be hashed, the first 5 characters of `foobar`
    expect($result)->toBe(['test' => '41cbe1a87981490351ccad5346d96da0ac10678670b31fc0ab209aed1b5bc515']);
});

it('doesn\'t truncate more than the string length', function (): void {
    $processor = new Hasher('sha256', 10);
    $result = $processor->scrubKeys($this->simpleExample->getInput(), $this->simpleExample->getSensitiveKeys());

    expect($result)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('doesn\'t truncate when length limit is 0', function (): void {
    $processor = new Hasher('sha256', 0);
    $result = $processor->scrubKeys($this->simpleExample->getInput(), $this->simpleExample->getSensitiveKeys());

    expect($result)->toBe(['test' => null]);
});

it('doesn\'t truncate when length limit is not set', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->simpleExample->getInput(), $this->simpleExample->getSensitiveKeys());

    expect($result)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('redacts nested arrays', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->nestedRedaction->getInput(), $this->nestedRedaction->getSensitiveKeys());

    expect($result)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']]);
});

it('keeps non redacted nested arrays intact', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->nestedNoHash->getInput(), $this->nestedNoHash->getSensitiveKeys());

    expect($result)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'no_hash' => 'foobar']]);
});

it('doesn\'t break on null values in input array', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->nestedNull->getInput(), $this->nestedNull->getSensitiveKeys());

    expect($result)->toBe(['test' => ['nested' => null, 'no_hash' => null, null]]);
});

it('doesn\'t break on null values in sensitive keys (array)', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->nestedSensitiveNull->getInput(), $this->nestedSensitiveNull->getSensitiveKeys());

    expect($result)->toBe($this->nestedSensitiveNull->getInput());
});

it('redacts inside nested arrays', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->insideNested->getInput(), $this->insideNested->getSensitiveKeys());

    expect($result)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']]);
});

// ExclusiveSubtree stories
it('it hashes all instances with exclusiveSubtree false in arrays', function (): void {
    $processor = new Hasher('sha256', null, false);
    $result = $processor->scrubKeys($this->exclusiveSubtree->getInput(), $this->exclusiveSubtree->getSensitiveKeys());

    expect($result)->toBe(['test_key' => 'test_value', 'test_subkey' => ['to_hash' => '4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006', 'test' => '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']]);
});

it('ensure exclusiveSubtree is turned on by default', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->exclusiveSubtree->getInput(), $this->exclusiveSubtree->getSensitiveKeys());

    expect($result)->toBe(['test_key' => 'test_value', 'test_subkey' => ['to_hash' => '4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006', 'test' => 'test']]);
});

it('preserves empty values in arrays', function (): void {
    $processor = new Hasher();
    $result = $processor->scrubKeys($this->optionalKeyExample->getInput(), $this->optionalKeyExample->getSensitiveKeys());

    expect($result)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'optionalKey' => null]);
});