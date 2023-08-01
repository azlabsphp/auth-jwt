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

interface RevokeTokenManager
{
    /**
     * Add the token (jti claim) to the list of revoked tokens.
     *
     * @return bool
     */
    public function add(AccessTokenEntity $token);

    /**
     * Determine whether the token exists in the list of revoked tokens.
     *
     * @return bool
     */
    public function has(AccessTokenEntity $payload);

    /**
     * Prune all revoked tokens.
     *
     * @return bool
     */
    public function clear();
}
