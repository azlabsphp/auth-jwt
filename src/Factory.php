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
        $this->claimsFactory = $claimsFactory ?? new ClaimsFactory();
        $this->refreshTokenTtl = $refreshTokenTtl ?? 20160;
    }

    /**
     * Creates an access Token manager.
     *
     * @throws InvalidKeyFileException
     * @throws MissingEncryptionFileException
     *
     * @return TokenManager
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
