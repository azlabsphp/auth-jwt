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

use Drewlabs\Contracts\OAuth\HasApiTokens;
use Psr\Http\Message\ServerRequestInterface;

interface TokenProvider
{
    /**
     * Retrieve authenticatable instance from psr7 request.
     *
     * @return HasApiTokens
     */
    public function findByRequest(ServerRequestInterface $request);

    /**
     * Retrieve authenticatable instance using bearer token string.
     *
     * @return HasApiTokens
     */
    public function findByBearerToken(string $bearerToken);
}
