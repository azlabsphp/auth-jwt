<?php

namespace Drewlabs\Auth\Jwt;

use Drewlabs\Auth\Jwt\Contracts\ClaimsConfigInterface;

class ClaimsConfig implements ClaimsConfigInterface
{
    /**
     * @var string
     */
    private $issuer;

    /**
     * @var int
     */
    private $ttl;

    /**
     * Creates claims config instance
     * 
     * @param string $issuer 
     * @param int $ttl 
     */
    public function __construct(string $issuer = null, $ttl = 360)
    {
        $this->issuer = $issuer ?? 'http://oauth.drewlabs.tg';
        $this->ttl = $ttl ?? 360;
    }

    /**
     * factory constructor implementation
     * 
     * @param array $attributes 
     * @return static 
     */
    public static function create(array $attributes)
    {
        return new static($attributes['issuer'] ?? 'http://oauth.drewlabs.tg', $attributes['ttl'] ?? 360);
    }

    /**
     * Returns claim issuer
     * 
     * @return string 
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * Returns claims time to live
     * 
     * @return int 
     */
    public function getTTl()
    {
        return $this->ttl;
    }
}
