<?php


namespace Drewlabs\Auth\Jwt;

use Drewlabs\Contracts\Jwt\ClaimsInterface;
use Drewlabs\Auth\Jwt\Contracts\ClaimsConfigInterface;
use Drewlabs\Auth\Jwt\Contracts\ClaimsFactoryInterface;
use Drewlabs\Auth\Jwt\Payload\Claims;

class ClaimsFactory implements ClaimsFactoryInterface
{
    public function create(ClaimsConfigInterface $config): ClaimsInterface
    {
        return new Claims($config->getIssuer(), $config->getTTl());
    }
}
