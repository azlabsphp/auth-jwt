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

namespace Drewlabs\Auth\Jwt\Contracts;

interface RevokedTokenStorageAdapter
{
    /**
     * Resolve a given value that match the key from the storage.
     *
     * @return AccessTokenEntity|null
     */
    public function get(string $key);

    /**
     * Add new revoked token to the storage.
     *
     * @return mixed
     */
    public function put(AccessTokenEntity $value);

    /**
     * Check if a value exists in the storage.
     */
    public function has(AccessTokenEntity $value): bool;

    /**
     * Clear all values from the storage.
     *
     * @return void
     */
    public function flush();
}
