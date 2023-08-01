<?php

namespace Drewlabs\Auth\Jwt\Contracts;

use Drewlabs\Contracts\OAuth\HasApiTokens;

interface UserProvider
{
    /**
     * Retrieve authenticatable instance by id
     * 
     * @param string $id 
     * 
     * @return HasApiTokens 
     */
    public function findById(string $id): ?HasApiTokens;
}