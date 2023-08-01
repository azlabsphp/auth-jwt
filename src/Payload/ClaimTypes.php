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

final class ClaimTypes
{
    /**
     * Payload issuer http ressource which is unique for each platform issuing the jwt token.
     */
    public const ISSUER = 'iss';

    /**
     * Timestamp representation of the moment the token was issue or created.
     */
    public const ISSUE_AT = 'iat';

    /**
     * Token expiration date. Must be after the "iat" for a valid token.
     */
    public const EXPIRATION = 'exp';

    /**
     * Token unique id.
     */
    public const JIT = 'jti';

    /**
     * Token should not be used before the corresponding time.
     */
    public const NOT_BEFORE = 'nbf';

    /**
     * The subject id.
     */
    public const SUBJECT = 'sub';

    /**
     * Custom Claim type holding token scopes.
     */
    public const SCOPES = 'scopes';

    /**
     * CSRF token signature.
     */
    public const XCSRF = 'xsrf';
}
