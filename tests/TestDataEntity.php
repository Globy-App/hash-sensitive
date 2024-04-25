<?php

namespace HashSensitiveTests;

/**
 * Class that contains a combination of input to be hashed and sensitive keys to hash with
 */
class TestDataEntity
{
    /**
     * @var array<array-key, mixed> $input
     */
    private array $input;
    /**
     * @var array<array-key, mixed> $sensitiveKeys
     */
    private array $sensitiveKeys;

    /**
     * @param array<array-key, mixed> $input          The input data to be hashed
     * @param array<array-key, mixed> $sensitiveKeys  Sensitive keys array
     */
    public function __construct(array $input, array $sensitiveKeys)
    {
        $this->input = $input;
        $this->sensitiveKeys = $sensitiveKeys;
    }

    /**
     * @return array<array-key, mixed>
     */
    public function getInput(): array
    {
        return $this->input;
    }

    /**
     * @return array<array-key, mixed>
     */
    public function getSensitiveKeys(): array
    {
        return $this->sensitiveKeys;
    }
}