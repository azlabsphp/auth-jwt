<?php

declare(strict_types=1);

/*
 * This file is part of the Drewlabs package.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

 namespace Drewlabs\Auth\Jwt\Contracts;

/**
 * Presonal Access Tokens writable persistence layer.
 * Implementations must write a serialized version of the PAT object
 * to a stateful storage.
 */
interface AccessTokenRepository
{
    /**
     * Save the personal access token details to disk.
     *
     * @return mixed
     */
    public function persist(AccessTokenEntity $entity);

    /**
     * Removes all revoked tokens from the storage.
     *
     * @return bool|void
     */
    public function prune();

    /**
     * Query a personnal access token by it jit.
     *
     * @param string $id
     *
     * @return AccessTokenEntity|null
     */
    public function findById($id);
}
