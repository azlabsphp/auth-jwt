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

use Drewlabs\Auth\Jwt\Contracts\ClaimsInterface;
use Drewlabs\Core\Helpers\DateTime;
use Drewlabs\Core\Helpers\Str;

class Claims implements ClaimsInterface
{
    /**
     * Payload issuer http ressource which is unique for each platform issuing the jwt token.
     *
     * @var string|mixed
     */
    protected $iss;

    /**
     * Refresh time to live of a token.
     *
     * @var int
     */
    protected $ttl;

    /**
     * List of the token default claims that are mandatory.
     *
     * @var array
     */
    protected $default_claims = [
        ClaimTypes::ISSUER,
        ClaimTypes::EXPIRATION,
        ClaimTypes::NOT_BEFORE,
        ClaimTypes::JIT,
        ClaimTypes::ISSUE_AT,
        ClaimTypes::XCSRF,
    ];

    /**
     * Payload claim object initialiser.
     *
     * @param string $issuer
     */
    public function __construct($issuer, $ttl = 360)
    {
        $this->iss = $issuer;
        $this->ttl = $ttl;
    }

    /**
     * Returns the payload issuer claim value.
     *
     * @return string
     */
    public function getiss()
    {
        return $this->iss;
    }

    /**
     * Set the token ttl (in minutes).
     *
     * @return static
     */
    public function setTTL(int $ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     */
    public function getTTL(): int
    {
        return $this->ttl;
    }

    /**
     * Return the list of default claims to be set on payloads.
     *
     * @return array
     */
    public function getDefaultClaims()
    {
        return $this->default_claims ?? [];
    }

    /**
     * Returns a payload from the default claims.
     *
     * @return array
     */
    public function toPayload(?array $claims = [])
    {
        $expires_at = $claims[ClaimTypes::EXPIRATION] ?? null;
        $issue_at = $claims[ClaimTypes::ISSUE_AT] ?? null;
        $payload = [
            ClaimTypes::ISSUER => $this->getiss(),
            ClaimTypes::EXPIRATION => $expires_at ?
                ($expires_at instanceof \DateTimeInterface ? $expires_at->getTimestamp() : $expires_at) :
                $this->exp(),
            ClaimTypes::NOT_BEFORE => $this->nbf(),
            ClaimTypes::JIT => $this->jti(),
            ClaimTypes::ISSUE_AT => $issue_at ?
                ($issue_at instanceof \DateTimeInterface ? $issue_at->getTimestamp() : $issue_at) :
                $this->iat(),
            ClaimTypes::XCSRF => $this->csrfToken(),
        ];
        $custom_claims_payload = [];
        foreach ($claims as $key => $value) {
            // Removes non-assoc entries and check if key is in the default claims
            if (\is_int($key) || \array_key_exists($key, $this->default_claims)) {
                continue;
            }
            $custom_claims_payload[$key] = $value;
        }
        $payload = array_merge($custom_claims_payload, $payload);

        return $payload;
    }

    /**
     * Set the Issued At (iat) claim.
     */
    private function iat(): int
    {
        return DateTime::nowTz()->getTimestamp();
    }

    /**
     * Set the Expiration (exp) claim.
     */
    private function exp(): int
    {
        return DateTime::addMinutes(DateTime::nowTz(), $this->ttl)->getTimestamp();
    }

    /**
     * Set the Not Before (nbf) claim.
     */
    private function nbf(): int
    {
        return DateTime::nowTz()->getTimestamp();
    }

    /**
     * Set a unique id (jti) for the token.
     *
     * @return string
     */
    private function jti(): ?string
    {
        return Str::base62encode(random_bytes(32));
    }

    /**
     * Generates a csrf token to validate token against request sources.
     *
     * @return string|false
     */
    private function csrfToken()
    {
        return Str::rand(40);
    }
}
