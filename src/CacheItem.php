<?php

declare(strict_types=1);

/*
 * This file is part of the drewlabs namespace.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Drewlabs\Auth\Jwt;

use Drewlabs\Core\Helpers\DateTime;

class CacheItem implements \JsonSerializable
{
    /**
     * @var mixed
     */
    private $value;

    /**
     * @var \DateTimeInterface
     */
    private $expiresAt;

    /**
     * @param mixed                  $value
     * @param \DateTimeInterface|int $expiresAt PHP datetime interface object or number of seconds after which the item
     *                                          should be mark as expired
     *
     * @return void
     */
    public function __construct($value, $expiresAt = null)
    {
        $this->value = $value;

        if (\is_string($expiresAt)) {
            $expiresAt = \DateTimeImmutable::createFromFormat(\DateTimeImmutable::ATOM, $expiresAt);
        }
        if (\is_int($expiresAt)) {
            $expiresAt = $expiresAt < 0 ?
                (new \DateTimeImmutable())->sub(new \DateInterval('PT'.abs($expiresAt).'S')) : (new \DateTimeImmutable())->add(new \DateInterval('PT'.$expiresAt.'S'));
        }
        $this->expiresAt = $expiresAt;
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    public function toArray()
    {
        return [
            'value' => $this->value,
            'expires_at' => $this->expiresAt ? $this->expiresAt->format(\DateTimeImmutable::ATOM) : null,
        ];
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param int $options
     *
     * @return string
     */
    public function toJson($options = 0)
    {
        return json_encode($this->toArray(), $options);
    }

    public function hasExpires(): bool
    {
        if (null === $this->expiresAt) {
            return false;
        }

        return DateTime::ispast($this->expiresAt);
    }
}
