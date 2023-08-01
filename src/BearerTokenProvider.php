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
use Drewlabs\Auth\Jwt\Contracts\AccessTokenRepository;
use Drewlabs\Auth\Jwt\Contracts\LastUsedStateAware;
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\Jwt\Contracts\TokenProvider;
use Drewlabs\Auth\Jwt\Contracts\UserProvider;
use Drewlabs\Auth\Jwt\Exceptions\DecodeTokenException;
use Drewlabs\Auth\Jwt\Exceptions\MissingRequiredPayloadClaimsException;
use Drewlabs\Auth\Jwt\Exceptions\MissingTokenException;
use Drewlabs\Auth\Jwt\Exceptions\RefreshTokenExpiredException;
use Drewlabs\Auth\Jwt\Exceptions\RefreshTokenNotFound;
use Drewlabs\Auth\Jwt\Exceptions\TokenExpiredException;
use Drewlabs\Auth\Jwt\Exceptions\TokenRevokedException;
use Drewlabs\Contracts\OAuth\HasApiTokens;
use Drewlabs\Core\Helpers\Reflector;
use Drewlabs\Core\Helpers\Str;
use Psr\Http\Message\ServerRequestInterface;

class BearerTokenProvider implements TokenProvider
{
    /**
     * @var TokenManagerInterface
     */
    private $tokens;

    /**
     * @var AccessTokenRepository|null
     */
    private $repository;

    /**
     * @var UserProvider
     */
    private $users;

    /**
     * Creates bearer token class instance.
     */
    public function __construct(TokenManagerInterface $tokens, UserProvider $users, AccessTokenRepository $repository = null)
    {
        $this->tokens = $tokens;
        $this->repository = $repository;
        $this->users = $users;
    }

    public function findByRequest(ServerRequestInterface $request)
    {
        $bearerToken = $this->getBearerTokenFromRequest($request);

        return $this->findByBearerToken((string) $bearerToken);
    }

    public function findByBearerToken(string $bearerToken)
    {
        try {
            $accessToken = $this->tokens->decodeToken($bearerToken);
            $tokenable = $this->users->findById((string) $accessToken->subject());
            if (
                !$this->supportsTokens($tokenable)
                || !$this->isValidAccessToken($accessToken)
            ) {
                return;
            }
            if (
                $this->repository
                && ($accessToken instanceof LastUsedStateAware)
            ) {
                $accessToken->lastUsedAt(new \DateTimeImmutable());
                $this->repository->persist($accessToken);
            }

            return $tokenable->withAccessToken($accessToken);
        } catch (\Throwable $e) {
            if ($this->isTokenException($e)) {
                return null;
            }
            throw $e;
        }
    }

    /**
     * Checks if exception is instance of token exception.
     *
     * @return bool
     */
    private function isTokenException(\Throwable $exception)
    {
        return $exception instanceof DecodeTokenException
            || $exception instanceof MissingRequiredPayloadClaimsException
            || $exception instanceof MissingTokenException
            || $exception instanceof RefreshTokenExpiredException
            || $exception instanceof RefreshTokenNotFound
            || $exception instanceof TokenExpiredException
            || $exception instanceof TokenRevokedException;
    }

    /**
     * Query for bearer token from psr7 server request instance.
     *
     * @param string $method
     * @param string $header
     * @param string $query
     *
     * @throws MissingTokenException
     *
     * @return string
     */
    private function getBearerTokenFromRequest(ServerRequestInterface $request, $method = 'bearer', $header = 'authorization', $query = 'token')
    {
        if ($token = $this->getBearerTokenFromHeaders($request, $header, $method)) {
            return $token;
        }
        if ($token = ($request->getQueryParams() ?? [])[$query] ?? null) {
            return $token;
        }
        if ($token = \is_object($body = ($request->getParsedBody() ?? [])) ? get_object_vars($body)[$query] ?? null : $body[$query] ?? null) {
            return $token;
        }
        throw new MissingTokenException('Token key not found');
    }

    /**
     * Parse token from the authorization header.
     *
     * @param ServerRequestInterface $request
     * @param string                 $header
     * @param string                 $method
     *
     * @return false|string
     */
    private function getBearerTokenFromHeaders($request, $header = 'authorization', $method = 'bearer')
    {
        $header = $request->getHeader($header);
        if (null === $header) {
            return false;
        }
        $header = array_pop($header);
        if (null === $header) {
            return false;
        }
        if (!Str::startsWith(strtolower($header), $method)) {
            return false;
        }

        return trim(str_ireplace($method, '', $header));
    }

    /**
     * Check if access token is valid.
     *
     * @return bool
     */
    private function isValidAccessToken(AccessTokenEntity $token)
    {
        return !$this->tokens->isRevoked($token);
    }

    /**
     * Determine if the tokenable model supports API tokens.
     *
     * @param mixed $tokenable
     *
     * @return bool
     */
    private function supportsTokens($tokenable = null)
    {
        if (null === $tokenable) {
            return false;
        }

        return $tokenable instanceof HasApiTokens || Reflector::usesRecursive($tokenable, 'withAccessToken');
    }
}
