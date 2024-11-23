<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use GlobyApp\HashSensitive\HashSensitiveProcessor;

it('redacts records contexts', function (): void {
    $processor = new HashSensitiveProcessor($this->simpleExample->getSensitiveKeys());

    $record = $this->getRecord(context: $this->simpleExample->getInput());
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('works without sensitive key subtrees', function (): void {
    $processor = new HashSensitiveProcessor($this->nestedExample->getSensitiveKeys());

    $record = $this->getRecord(context: $this->nestedExample->getInput());
    expect($processor($record)->context)->toBe(['test' => 'c413de2c94a3a668b82ae2207da4b6961eeeccaff97623e2143d978610cb4746']);
});

it('truncates masked characters', function (): void {
    $processor = new HashSensitiveProcessor($this->simpleExample->getSensitiveKeys(), lengthLimit: 5);

    $record = $this->getRecord(context: $this->simpleExample->getInput());
    // Only `fooba` should be hashed, the first 5 characters of `foobar`
    expect($processor($record)->context)->toBe(['test' => '41cbe1a87981490351ccad5346d96da0ac10678670b31fc0ab209aed1b5bc515']);
});

it('doesn\'t truncate more than the string length', function (): void {
    $processor = new HashSensitiveProcessor($this->simpleExample->getSensitiveKeys(), lengthLimit: 10);

    $record = $this->getRecord(context: $this->simpleExample->getInput());
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('doesn\'t truncate when length limit is 0', function (): void {
    $processor = new HashSensitiveProcessor($this->simpleExample->getSensitiveKeys(), lengthLimit: 0);

    $record = $this->getRecord(context: $this->simpleExample->getInput());
    expect($processor($record)->context)->toBe(['test' => null]);
});

it('doesn\'t truncate when length limit is not set', function (): void {
    $processor = new HashSensitiveProcessor($this->simpleExample->getSensitiveKeys(), lengthLimit: null);

    $record = $this->getRecord(context: $this->simpleExample->getInput());
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('redacts nested arrays', function (): void {
    $processor = new HashSensitiveProcessor($this->nestedRedaction->getSensitiveKeys());

    $record = $this->getRecord(context: $this->nestedRedaction->getInput());
    expect($processor($record)->context)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']]);
});

it('keeps non redacted nested arrays intact', function (): void {
    $processor = new HashSensitiveProcessor($this->nestedNoHash->getSensitiveKeys());

    $record = $this->getRecord(context: $this->nestedNoHash->getInput());
    expect($processor($record)->context)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'no_hash' => 'foobar']]);
});

it('doesn\'t break on null values in input array', function (): void {
    $processor = new HashSensitiveProcessor($this->nestedNull->getSensitiveKeys());

    $record = $this->getRecord(context: $this->nestedNull->getInput());
    expect($processor($record)->context)->toBe(['test' => ['nested' => null, 'no_hash' => null, null]]);
});

it('doesn\'t break on null values in sensitive keys (array)', function (): void {
    $processor = new HashSensitiveProcessor($this->nestedSensitiveNull->getSensitiveKeys());

    $record = $this->getRecord(context: $this->nestedSensitiveNull->getInput());
    expect($processor($record)->context)->toBe($this->nestedSensitiveNull->getInput());
});

it('redacts inside nested arrays', function (): void {
    $processor = new HashSensitiveProcessor($this->insideNested->getSensitiveKeys());

    $record = $this->getRecord(context: $this->insideNested->getInput());
    expect($processor($record)->context)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']]);
});

# Prevent bugs from re-appearing
# Issue: https://github.com/Globy-App/hash-sensitive/issues/10
it('does not hash values of integer keys', function (): void {
    $integerKeys = new TestDataEntity([0 => 'foo', 1 => 'bar'], ['other', 'first', 'second']);
    $processor = new HashSensitiveProcessor($integerKeys->getSensitiveKeys());

    $record = $this->getRecord(context: $integerKeys->getInput());
    expect($processor($record)->context)->toBe(['test' => [0 => 'foo', 1 => 'bar']]);
});

it('does not throw an exception', function (): void {
    $integerKeys = new TestDataEntity([0 => ['id' => 1, 'value' => 'foo'], 1 => ['id' => 2, 'value' => 'bar']], ['other', 'first', 'second']);
    $processor = new HashSensitiveProcessor($integerKeys->getSensitiveKeys());

    $record = $this->getRecord(context: $integerKeys->getInput());
    expect($processor($record)->context)->toBe(['test' => [0 => ['id' => 1, 'value' => 'foo'], 1 => ['id' => 2, 'value' => 'bar']]]);
});