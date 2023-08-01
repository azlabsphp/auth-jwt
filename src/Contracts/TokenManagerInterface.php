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

interface TokenManagerInterface
{
    /**
     * Decode user provided access token string returning composed claims.
     *
     * @param string $token
     *
     * @return AccessTokenEntity
     */
    public function decodeToken($token);

    /**
     * Generates a personal access token from provided claims.
     *
     * @param array|object $claims
     *
     * @throws \Exception;
     *
     * @return \JsonSerializable
     */
    public function createToken($claims);

    /**
     * Regenerate user provided token with new expiration date and claims.
     *
     * @param string $token
     *
     * @throws \Exception;
     *
     * @return \JsonSerializable
     */
    public function refreshToken($token);

    /**
     * Revoke the user provided token.
     *
     * @param string $token
     *
     * @return bool
     */
    public function revokeToken($token);

    /**
     * Check if a plain text token is revoked.
     *
     * @return bool
     */
    public function isRevoked(AccessTokenEntity $token);
}
