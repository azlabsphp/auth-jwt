<?php


namespace Drewlabs\Auth\Jwt;

use Drewlabs\Auth\Jwt\Contracts\ClaimsFactoryInterface;
use Drewlabs\Auth\Jwt\Exceptions\InvalidKeyFileException;
use Drewlabs\Auth\Jwt\Exceptions\MissingEncryptionFileException;
use Drewlabs\Auth\Jwt\Payload\PayloadFactory;
use Drewlabs\Auth\Jwt\Providers\JWT;
use Drewlabs\Auth\Jwt\Providers\KeyFactory;

class Factory
{
    /**
     * @var ClaimsFactoryInterface
     */
    private $claimsFactory;

    /**
     * @var int
     */
    private $refreshTokenTtl;

    public function __construct(ClaimsFactoryInterface $claimsFactory = null, int $refreshTokenTtl = 20160)
    {
        $this->claimsFactory = $claimsFactory ?? new ClaimsFactory;
        $this->refreshTokenTtl = $refreshTokenTtl ?? 20160;
    }

    /**
     * Creates an access Token manager
     * 
     * @param array $config 
     * @return TokenManager 
     * @throws InvalidKeyFileException 
     * @throws MissingEncryptionFileException 
     */
    public function create(array $config = [])
    {
        return new TokenManager(
            new JWT(KeyFactory::create($config)),
            new PayloadFactory($this->claimsFactory->create(new ClaimsConfig($config['issuer'] ?? null, $config['accessToken']['tokenTTL'] ?? 360))),
            $config['accessToken']['refreshTTL'] ?? $this->refreshTokenTtl
        );
    }
}