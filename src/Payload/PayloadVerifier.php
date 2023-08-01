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

namespace Drewlabs\Auth\Jwt\Payload;

use Drewlabs\Contracts\Jwt\PayloadFactoryInterface;
use Drewlabs\Contracts\Jwt\PayloadVerifier as JwtPayloadVerifier;
use Drewlabs\Core\Helpers\Str;

class PayloadVerifier implements JwtPayloadVerifier
{
    /**
     * Payload factory instance provider.
     *
     * @var PayloadFactoryInterface
     */
    protected $factory;

    /**
     * PayloadVerifier interface object initializer.
     */
    public function __construct(PayloadFactoryInterface $factory)
    {
        $this->factory = $factory;
    }

    /**
     * Checks if payload created from token has at least default claims
     * and the issuer attribute equals to the configured issuer.
     *
     * @param array|\JsonSerializable $payload
     *
     * @return bool
     */
    public function verify(array $payload)
    {
        $claims = $this->factory->getClaims();
        if (\count(array_intersect(array_keys($payload), $claims->getDefaultClaims())) !== \count($claims->getDefaultClaims())) {
            return false;
        }
        if (!\is_string($payload[ClaimTypes::ISSUER] ?? null) || !Str::same($payload[ClaimTypes::ISSUER] ?? null, $claims->getiss())) {
            return false;
        }
        return true;
    }
}
