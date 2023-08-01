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

namespace Drewlabs\Auth\Jwt\Exceptions;

class MissingRequiredPayloadClaimsException extends TokenException
{
    /**
     * Creates exception class instance
     * 
     */
    public function __construct()
    {
        parent::__construct('Default payload claims missing from the provided payload');
    }
}
