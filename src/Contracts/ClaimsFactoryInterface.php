<?php

namespace Drewlabs\Auth\Jwt\Contracts;

use Drewlabs\Contracts\Jwt\ClaimsInterface;

interface ClaimsFactoryInterface
{
    /**
     * Creates jwt claims from array configurations
     * 
     * @param ClaimsConfigInterface $config 
     * @return ClaimsInterface 
     */
    public function create(ClaimsConfigInterface $config): ClaimsInterface;
}
