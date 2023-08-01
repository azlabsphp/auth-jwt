<?php

namespace Drewlabs\Auth\Jwt\Contracts;

interface ClaimsConfigInterface
{
    /**
     * Returns claim issuer
     * 
     * @return string 
     */
    public function getIssuer();

    /**
     * Returns claims time to live
     * 
     * @return int 
     */
    public function getTTl();
}