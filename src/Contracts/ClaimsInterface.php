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

interface ClaimsInterface
{
    /**
     * Returns the payload issuer claim value.
     *
     * @return string
     */
    public function getiss();

    /**
     * Set the token ttl (in minutes).
     *
     * @return static
     */
    public function setTTL(int $ttl);

    /**
     * Get the token ttl.
     */
    public function getTTL(): int;

    /**
     * Return the list of default claims to be set on payloads.
     *
     * @return array
     */
    public function getDefaultClaims();

    /**
     * Returns a payload from the default claims.
     *
     * @return array
     */
    public function toPayload(array $custom_claims = null);
}
