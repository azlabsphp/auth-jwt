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

namespace Drewlabs\Auth\Jwt\Contracts;

use Drewlabs\Contracts\OAuth\Token;
use JsonSerializable;

interface AccessTokenEntity extends Token, JsonSerializable
{
    /**
     * Personal access token abilities|scope getter/setter.
     *
     * @return mixed
     */
    public function abilities(array $values = []);

    /**
     * Personal access token subject a.k.a user identity getter/setter.
     *
     * @param string|int|null $sub
     *
     * @return string|int|null
     */
    public function subject($sub = null);

    /**
     * Personal access token jti getter/setter.
     *
     * @return string|null
     */
    public function id(string $value = null);

    /**
     * @param string|\DatetimeInterface|null $value
     *
     * @return \DatetimeInterface
     */
    public function expiresAt($value = null);

    /**
     * @param string|\DatetimeInterface|int|null $value
     *
     * @return \DatetimeInterface
     */
    public function issuedAt($value = null);

    /**
     * @param string|null $value
     *
     * @return string
     */
    public function issuer($value = null);

    /**
     * @return bool
     */
    public function revoked();

    /**
     * @return self
     */
    public function markAsRevoked();

    /**
     * Returns array representation of the instance.
     *
     * @return array
     */
    public function toArray();
}
