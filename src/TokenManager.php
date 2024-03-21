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
use Drewlabs\Auth\Jwt\Contracts\JWTInterface;
use Drewlabs\Auth\Jwt\Contracts\PayloadFactoryInterface;
use Drewlabs\Auth\Jwt\Contracts\RevokeTokenManager;
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\Jwt\Exceptions\MissingRequiredPayloadClaimsException;
use Drewlabs\Auth\Jwt\Exceptions\TokenExpiredException;
use Drewlabs\Auth\Jwt\Exceptions\TokenRevokedException;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\Jwt\Contracts\PayloadVerifier as AbstractPayloadVerifier;
use Drewlabs\Auth\Jwt\Payload\PayloadVerifier;
use Drewlabs\Core\Helpers\DateTime;

final class TokenManager implements TokenManagerInterface
{
    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int
     */
    public $refreshTTL;

    /**
     * Token encoder and decoder provider.
     *
     * @var JWTInterface;
     */
    private $jwt;

    /**
     * Blacklist provider.
     *
     * @var RevokeTokenManager
     */
    private $revokeTokens;

    /**
     * Payload factory provider.
     *
     * @var PayloadFactoryInterface
     */
    private $factory;

    /**
     * @var AbstractPayloadVerifier
     */
    private $payloadVerifier;

    /**
     * Create tokens manager instance.
     *
     * @return void
     */
    public function __construct(
        JWTInterface $jwt,
        PayloadFactoryInterface $factory,
        int $ttl = 20160
    ) {
        $this->jwt = $jwt;
        $this->revokeTokens = new RevokedTokens($ttl);
        $this->factory = $factory;
        $this->payloadVerifier = new PayloadVerifier($factory);
        $this->refreshTTL = $ttl;
    }

    public function decodeToken($token)
    {
        $accessToken = $this->createAccessToken($this->jwt->decode($token));
        if ($this->revokeTokens->has($accessToken)) {
            throw new TokenRevokedException('Unable to decode the token, it has been blacklisted');
        }

        return $accessToken;
    }

    /**
     * {@inheritDoc}
     *
     * @return NewAccessToken
     */
    public function createToken($claims)
    {
        $payload = $this->factory->make($claims);
        $plainTextToken = $this->jwt->encode((array) $payload);

        return $this->createNewAccessToken($payload, $plainTextToken);
    }

    public function refreshToken($token)
    {
        $accessToken = $this->decodeToken($token);
        $tokenHasExpired = DateTime::ispast(DateTime::addMinutes(DateTime::timestamp($accessToken[ClaimTypes::ISSUE_AT]), $this->refreshTTL));
        if ($tokenHasExpired) {
            throw new TokenExpiredException('Cannot refresh token, refresh time expired');
        }
        $this->revokeTokens->add($accessToken);

        return $this->createToken(
            $this->factory->make(
                [
                    ClaimTypes::SUBJECT => $accessToken[ClaimTypes::SUBJECT],
                    ClaimTypes::ISSUE_AT => $accessToken[ClaimTypes::ISSUE_AT],
                ],
            )
        );
    }

    public function revokeToken($token)
    {
        return $this->revokeTokens->add($this->decodeToken($token));
    }

    public function isRevoked(AccessTokenEntity $token)
    {
        return $this->revokeTokens->has($token);
    }

    /**
     * @param object|array $payload
     *
     * @return AccessToken
     */
    private function createAccessToken($payload)
    {
        if (!$this->payloadVerifier->verify(\is_object($payload) ? get_object_vars($payload) : $payload)) {
            throw new MissingRequiredPayloadClaimsException();
        }

        return new AccessToken($payload);
    }

    /**
     * @param object|array $payload
     * @param string       $plainTextToken
     *
     * @return NewAccessToken
     */
    private function createNewAccessToken($payload, $plainTextToken)
    {
        return new NewAccessToken($this->createAccessToken($payload), $plainTextToken);
    }
}
