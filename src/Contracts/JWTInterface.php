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

interface JWTInterface
{
    /**
     * Convertis et signe un objet PHP ou un tableau en une chaine de charactère JWT.
     *
     * @param object|array $payload PHP object or array
     *
     * @return string A signed JWT
     */
    public function encode($payload);

    /**
     * Convertis une chaine charactère JWT en un objet PHP.
     *
     * @return array|object The JWT's payload as a PHP object
     */
    public function decode($token);
}
