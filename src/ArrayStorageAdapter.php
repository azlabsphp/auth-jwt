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

use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\RevokedTokenStorageAdapter;

class ArrayStorageAdapter implements RevokedTokenStorageAdapter
{
    /**
     * @var array<string,CacheItem>
     */
    private $cache = [];

    public function get(string $key)
    {
        return $this->cache[$key] ?? null;
    }

    public function put(AccessTokenEntity $value)
    {
        $this->cache[$value->id()] = new CacheItem($value->markAsRevoked());
    }

    public function has(AccessTokenEntity $value): bool
    {
        if (!\array_key_exists($value->id(), $this->cache)) {
            return false;
        }

        return !$this->cache[$value->id()]->hasExpires();
    }

    public function flush()
    {
        $this->cache = [];
    }
}
