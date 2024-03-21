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

interface PayloadVerifier
{
    /**
     * Check if payload generated from the token decode operation has valid values.
     *
     * @param array|object $payload
     *
     * @return bool
     */
    public function verify(array $payload);
}
