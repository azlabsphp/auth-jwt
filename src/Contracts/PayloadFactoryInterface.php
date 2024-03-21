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

interface PayloadFactoryInterface
{
    /**
     * Returns payload claims instance.
     *
     * @return IClaims
     */
    public function getClaims();

    /**
     * Set the token ttl (in minutes).
     *
     * @return static
     */
    public function setPayloadTTL(int $ttl);

    /**
     * Set the refresh flow.
     *
     * @return self
     */
    public function setRefreshFlow(bool $refresh_flow = true);

    /**
     * Generate a payload with default claims and user provided custom claims.
     *
     * @return array|object
     */
    public function make(array $claims = []);
}
