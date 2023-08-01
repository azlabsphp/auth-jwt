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

namespace Drewlabs\Auth\Jwt;

use Drewlabs\Contracts\OAuth\Token;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;

/**
 * @method bool revoke()
 * @method bool transient()
 * @method bool can($ability)
 * @method bool cant($ability)
 * @method bool revoked()
 * @method void markAsRevoked()
 */
class NewAccessToken implements \JsonSerializable
{
    /**
     * @var AccessTokenEntity
     */
    public $accessToken;

    /**
     * @var string
     */
    public $plainTextToken;

    /**
     * 
     * @param Token $token 
     * @param null|string $plainTextToken 
     * @return self 
     */
    public function __construct(Token $token, ?string $plainTextToken = null)
    {
        $this->accessToken = $token;
        $this->plainTextToken = $plainTextToken;
    }

    public function __get($name)
    {
        return $this->accessToken->{$name};
    }

    public function __call($name, $arguments)
    {
        return $this->accessToken->{$name}(...$arguments);
    }

    /**
     * Get the instance as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return array_merge(['authToken' => $this->plainTextToken], $this->accessToken->toArray() ?? []);
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @return string
     */
    public function toJson($flags = 0, $depth = 512)
    {
        return json_encode($this->toArray(), $flags, $depth);
    }
}
