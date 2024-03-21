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

namespace Drewlabs\Auth\Jwt;

use Drewlabs\Auth\Jwt\Contracts\ClaimsConfigInterface;
use Drewlabs\Auth\Jwt\Contracts\ClaimsFactoryInterface;
use Drewlabs\Auth\Jwt\Contracts\ClaimsInterface;
use Drewlabs\Auth\Jwt\Payload\Claims;

class ClaimsFactory implements ClaimsFactoryInterface
{
    public function create(ClaimsConfigInterface $config): ClaimsInterface
    {
        return new Claims($config->getIssuer(), $config->getTTl());
    }
}
