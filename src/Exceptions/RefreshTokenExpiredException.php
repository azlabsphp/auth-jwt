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

namespace Drewlabs\Auth\Jwt\Exceptions;

class RefreshTokenExpiredException extends TokenException
{
    /**
     * Creates exception class instance.
     *
     * @param string $message
     * @param int    $code
     */
    public function __construct($message = 'Unauthorized access, refresh token has expired', $code = 401)
    {
        parent::__construct($message, $code);
    }
}
