<?php

namespace HashSensitiveTests;

/**
 * Class that contains a combination of input to be hashed and sensitive keys to hash with
 */
class TestDataEntity
{
    private array $input;
    private array $sensitiveKeys;

    /**
     * @param array $input          The input data to be hashed
     * @param array $sensitiveKeys  Sensitive keys array
     */
    public function __construct(array $input, array $sensitiveKeys)
    {
        $this->input = $input;
        $this->sensitiveKeys = $sensitiveKeys;
    }

    public function getInput(): array
    {
        return $this->input;
    }

    public function getSensitiveKeys(): array
    {
        return $this->sensitiveKeys;
    }
}