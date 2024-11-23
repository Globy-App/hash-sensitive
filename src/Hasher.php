<?php

namespace GlobyApp\HashSensitive;

use UnexpectedValueException;

/**
 * Class to manage scrubbing the keys from an array
 *
 * @api
 * @author sjustein
 */
class Hasher
{
    private ?int $lengthLimit;
    private string $algorithm;
    private bool $exclusiveSubtree;

    public function __construct(string $algorithm = 'sha256', ?int $lengthLimit = null, bool $exclusiveSubtree = true)
    {
        $this->algorithm = $algorithm;
        $this->lengthLimit = $lengthLimit;
        $this->exclusiveSubtree = $exclusiveSubtree;
    }

    /**
     * Function to hash sensitive keys in an input array
     *
     * @param array<array-key, mixed> $inputArray    The array to hash values in
     * @param array<array-key, mixed> $sensitiveKeys The keys to hash
     *
     * @return array<array-key, mixed> The input array with sensitive keys hashed
     */
    public function scrubKeys(array $inputArray, array $sensitiveKeys): array
    {
        return $this->traverseInputArray($inputArray, $sensitiveKeys);
    }

    /**
     * Function to hash the input value, using the specified hashing algorithm and length limit
     *
     * @param string $value The value to hash
     *
     * @return string|null The hashed value, or null, if the input string was empty
     */
    protected function hash(string $value): ?string
    {
        if (strlen($value) === 0) {
            return null;
        }

        // Cut the input to the length limit specified
        $cutInput = substr($value, 0, $this->lengthLimit);

        if (strlen($cutInput) === 0) {
            return null;
        }

        return hash($this->algorithm, $cutInput);
    }

    /**
     * Function to handle traversing arrays and objects
     *
     * @param array<array-key, mixed>|object $value         The value of the key in the input data
     * @param array<array-key, mixed>        $sensitiveKeys The list of keys to hash
     *
     * @throws UnexpectedValueException if $value was not either an array of an object
     *
     * @return array<array-key, mixed>|object The processed array or object
     */
    protected function traverse(array|object $value, array $sensitiveKeys): array|object
    {
        if (is_array($value)) {
            return $this->traverseInputArray($value, $sensitiveKeys);
        }

        return $this->traverseObject($value, $sensitiveKeys);
    }

    /**
     * Traverse an array and replace all values to be redacted with a hashed version of the value
     *
     * @param array<array-key, mixed> $inputArray    Array to redact values from
     * @param array<array-key, mixed> $sensitiveKeys Keys to redact
     *
     * @return array<array-key, mixed> Input array with redacted values hashed
     */
    protected function traverseInputArray(array $inputArray, array $sensitiveKeys): array
    {
        foreach ($inputArray as $key => $value) {
            if ($value === null) {
                // Nothing to hash or process
                continue;
            }

            // If the value is not an array or an object, hash it if it is a sensitive key
            if (is_scalar($value)) {
                if ($this->isSensitiveKey($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->hash(print_r($value, true));
                }

                continue;
            }

            // The value is either an array or an object, let traverse handle the specifics
            // If the current key is a sensitive key, traverse the subtree.
            if ($this->isSensitiveKey($key, $sensitiveKeys)) {
                // If the current key doesn't have a subtree of sensitive keys (indicating the entire subtree,
                //  and not a value somewhere in the subtree should be hashed)
                if (!array_key_exists($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->hash(print_r($value, true));

                    // Continue to the next value, as there is no subtree or sub-object to traverse
                    continue;
                }

                /* @phpstan-ignore-next-line The above if statement asserts that $sensitiveKeys[$key] is a subtree */
                $inputArray[$key] = $this->traverse($value, $sensitiveKeys[$key]);

                // ExclusiveSubtree turned off means that sub keys should be checked according to ALL keys, not just
                // the keys in their sensitive keys subtree
                if (!$this->exclusiveSubtree) {
                    $inputArray[$key] = $this->traverse($inputArray[$key], $sensitiveKeys);
                }

                continue;
            }

            // The current key is not a sensitive key, traverse the subtree in search of sensitive keys with the same level in sensitiveKeys
            /* @phpstan-ignore-next-line is_scalar above this if block asserts that $value is not a scalar */
            $inputArray[$key] = $this->traverse($value, $sensitiveKeys);
        }

        return $inputArray;
    }

    /**
     * Traverse an object and replace all values to be redacted with a hashed version of the value
     *
     * @param object $object            Object to redact values from
     * @param array<array-key, mixed>  $sensitiveKeys Keys for which to hash the value
     *
     * @return object The object with redacted values hashed
     */
    protected function traverseObject(object $object, array $sensitiveKeys): object
    {
        foreach (get_object_vars($object) as $key => $value) {
            if ($value === null) {
                // Nothing to hash or process
                continue;
            }

            // If the value is not an array or an object, hash it if it is a sensitive key
            if (is_scalar($value)) {
                if (in_array($key, $sensitiveKeys) || array_key_exists($key, $sensitiveKeys)) {
                    $object->{$key} = $this->hash(print_r($value, true));
                }

                continue;
            }

            // The value is either an array or an object, let traverse handle the specifics
            // If the current key is a sensitive key, traverse the sub-object.
            if (in_array($key, $sensitiveKeys) || array_key_exists($key, $sensitiveKeys)) {
                // If the current key doesn't have a subtree of sensitive keys (indicating the entire sub-object,
                //  and not a value somewhere in the sub-object should be hashed)
                if (!array_key_exists($key, $sensitiveKeys)) {
                    $object->{$key} = $this->hash(print_r($value, true));

                    // Continue to the next value, as there is no subtree or sub-object to traverse
                    continue;
                }

                /* @phpstan-ignore-next-line The above if statement asserts that $sensitiveKeys[$key] is a subtree */
                $object->{$key} = $this->traverse($value, $sensitiveKeys[$key]);

                // ExclusiveSubtree turned off means that sub keys should be checked according to ALL keys, not just
                // the keys in their sensitive keys sub-object
                if (!$this->exclusiveSubtree) {
                    $object->{$key} = $this->traverse($object->{$key}, $sensitiveKeys);
                }

                continue;
            }

            // The current key is not a sensitive key, traverse the sub-object in search of sensitive keys with the same level in sensitiveKeys
            /* @phpstan-ignore-next-line is_scalar above this if block asserts that $value is not a scalar */
            $object->{$key} = $this->traverse($value, $sensitiveKeys);
        }

        return $object;
    }

    /**
     * @param int|string $key
     *
     * @param array<array-key, mixed> $sensitiveKeys Keys to redact
     *
     * @return bool Whether the key provided is a sensitiveKey
     */
    protected function isSensitiveKey(int|string $key, array $sensitiveKeys): bool
    {
        // Checks the values, if the key is in the value list of sensitive keys (the 'end' of the sensitive key lists)
        if (in_array($key, $sensitiveKeys)) {
            return true;
        }

        // When there is a sub array, check whether the key is in the sensitive key key list
        if (array_key_exists($key, $sensitiveKeys)) {
            if (is_int($key)) {
                // If the key is an integer, this is php generated key, when sensitiveKeys should be a value list
                return false;
            }

            return true;
        }

        return false;
    }
}
