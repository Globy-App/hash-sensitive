<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use Monolog\DateTimeImmutable;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Log\LogLevel;
use Stringable;

abstract class TestCase extends BaseTestCase
{
    protected TestDataEntity $simpleExample;
    protected TestDataEntity $nestedExample;
    protected TestDataEntity $nestedRedaction;
    protected TestDataEntity $nestedNoHash;
    protected TestDataEntity $nestedNull;
    protected TestDataEntity $nestedSensitiveNull;
    protected TestDataEntity $insideNested;
    protected TestDataEntity $exclusiveSubtree;
    protected TestDataEntity $optionalKeyExample;

    public function __construct(string $name)
    {
        $this->simpleExample = new TestDataEntity(['test' => 'foobar'], ['test']);
        $this->nestedExample = new TestDataEntity(['test' => ['foobar' => 'test']], ['test']);
        $this->nestedRedaction = new TestDataEntity(['test' => ['nested' => 'foobar']], ['test' => ['nested']]);
        $this->nestedNoHash = new TestDataEntity(['test' => ['nested' => 'foobar', 'no_hash' => 'foobar']], ['test' => ['nested']]);
        $this->nestedNull = new TestDataEntity(['test' => ['nested' => null, 'no_hash' => null, null]], ['test' => ['nested']]);
        $this->nestedSensitiveNull = new TestDataEntity(['test' => ['nested' => null, 'no_hash' => null, null]], ['test' => [null], null]);
        $this->insideNested = new TestDataEntity(['test' => ['nested' => 'foobar']], ['nested']);
        $this->exclusiveSubtree = new TestDataEntity(['test_key' => 'test_value', 'test_subkey' => ['to_hash' => 'test_value', 'test' => 'test']], ['test', 'test_subkey' => ['to_hash']]);
        $this->optionalKeyExample = new TestDataEntity(['test' => 'foobar', 'optionalKey' => ''], ['test', 'optionalKey']);

        parent::__construct($name);
    }

    /**
     * @param value-of<Level::VALUES>|value-of<Level::NAMES>|Level|LogLevel::* $level
     * @param string|Stringable $message
     * @param array<array-key, mixed> $context
     * @param string $channel
     * @param \DateTimeImmutable $datetime
     * @param array<array-key, mixed> $extra
     * @return LogRecord
     */
    protected function getRecord(string|int|Level $level = Level::Warning, string|Stringable $message = 'test', array $context = [], string $channel = 'test', \DateTimeImmutable $datetime = new DateTimeImmutable(true), array $extra = []): LogRecord
    {
        return new LogRecord(
            datetime: $datetime,
            channel: $channel,
            level: Logger::toMonologLevel($level),
            message: (string) $message,
            context: $context,
            extra: $extra,
        );
    }
}
