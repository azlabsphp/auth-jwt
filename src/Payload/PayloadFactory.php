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

namespace Drewlabs\Auth\Jwt\Payload;

use Drewlabs\Contracts\Jwt\ClaimsInterface;
use Drewlabs\Contracts\Jwt\PayloadFactoryInterface;

class PayloadFactory implements PayloadFactoryInterface
{
    /**
     * Default payload claims.
     *
     * @var ClaimsInterface
     */
    protected $claims;

    /**
     * Set to make a token refresh flow.
     *
     * @var bool
     */
    protected $refreshFlow = false;

    /**
     * Actual token payload.
     *
     * @var array|object
     */
    protected $payload;

    /**
     * Payload factory instance initialiser.
     */
    public function __construct(ClaimsInterface $claims)
    {
        $this->claims = $claims;
    }

    public function make($claims = [])
    {
        return $this->claims->toPayload($claims);
    }

    /**
     * Returns payload claims instance.
     *
     * @throws \RuntimeException
     *
     * @return ClaimsInterface
     */
    public function getClaims()
    {
        if (isset($this->claims)) {
            return $this->claims;
        }
        throw new \RuntimeException(__CLASS__.' is not properly constructed ');
    }

    /**
     * Set the token ttl (in minutes).
     *
     * @return static
     */
    public function setPayloadTTL(int $ttl)
    {
        $this->claims = $this->claims->setTTL($ttl);

        return $this;
    }

    /**
     * Set the refresh flow.
     *
     * @return $this
     */
    public function setRefreshFlow(bool $refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
