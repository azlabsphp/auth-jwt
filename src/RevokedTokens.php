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

use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\RevokeTokenManager;
use Drewlabs\Auth\JwtOauth\Contracts\RevokedTokenStorageAdapter;
use Drewlabs\Core\Helpers\DateTime;

class RevokedTokens implements RevokeTokenManager
{
    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int
     */
    public $refreshTTL;

    /**
     * @var RevokedTokenStorageAdapter
     */
    protected $adapter;

    /**
     * @param int $ttl total minutes from issue date in which a JWT can be refreshed
     *
     * @return void
     */
    public function __construct($ttl = 20160)
    {
        $this->adapter = RevokedTokenStorageAdapters::getInstance()->default();
        $this->setRefreshTTL($ttl);
    }

    public function has(AccessTokenEntity $payload)
    {
        return $this->adapter->has($payload);
    }

    public function add(AccessTokenEntity $token)
    {
        $exp = $token->expiresAt();
        $refresh_exp = DateTime::addMinutes(
            $token->issuedAt(),
            $this->refreshTTL
        );
        // No need to blacklist token if already expired
        if (DateTime::ispast($exp) && DateTime::ispast($refresh_exp)) {
            return false;
        }
        // TODO: Revoke the token
        return $this->adapter->put($token);
    }

    public function clear()
    {
        $this->adapter->flush();

        return true;
    }

    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = (int) $ttl;
    }
}
