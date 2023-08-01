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

use DateTimeInterface;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\CsrfTokenAware;
use Drewlabs\Auth\Jwt\Contracts\LastUsedStateAware;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;

class AccessToken implements AccessTokenEntity, LastUsedStateAware, CsrfTokenAware
{
    /**
     * @var string[]
     */
    private $scopes = [];

    /**
     * Subject for which the token has been generated.
     *
     * @var string|int
     */
    private $sub = null;

    /**
     * @var string
     */
    private $jti = null;

    /**
     * @var string|\DateTimeInterface
     */
    private $expiresAt_ = null;

    /**
     * @var string|\DateTimeInterface
     */
    private $iat;

    /**
     * Token issuer.
     *
     * @var string
     */
    private $iss = 'http://localhost';

    /**
     * Token revoke status.
     *
     * @var bool
     */
    private $revoked = false;

    /**
     * @var \DateTimeInterface
     */
    private $last_used_at;

    /**
     * CSRF Token identifier.
     *
     * @var string
     */
    private $token_;

    /**
     * @param array|object|mixed $payload
     *
     * @return self
     */
    public function __construct($payload = [])
    {
        $is_object = \is_object($payload);
        if ($is_object && method_exists($payload, 'toArray')) {
            $payload = $payload->toArray();
        }
        if ($is_object) {
            $payload = get_object_vars($payload);
        }
        $this->setClaimTypeValues($payload);
    }

    public function revoke()
    {
        RevokedTokenStorageAdapters::getInstance()->default()->put($this);

        return true;
    }

    public function transient()
    {
        return false;
    }

    public function can($ability)
    {
        $abilities = $this->abilities();

        return \in_array('*', $abilities, true) ||
            \array_key_exists($ability, array_flip($abilities));
    }

    public function cant($ability)
    {
        return !$this->can($ability);
    }

    public function abilities(array $values = [])
    {
        if (!empty($values)) {
            $this->scopes = $values;
        }

        return empty($this->scopes) ? [] : $this->scopes;
    }

    public function subject($sub = null)
    {
        if (null !== $sub) {
            $this->sub = $sub;
        }

        return $this->sub;
    }

    public function id(?string $value = null)
    {
        if (null !== $value) {
            $this->jti = $value;
        }

        return $this->jti;
    }

    public function expiresAt($value = null)
    {
        if (null !== $value) {
            $this->expiresAt_ = \is_int($value) ?
                new \DateTimeImmutable(date(\DateTimeImmutable::ATOM, $value)) : (\is_string($value) ? new \DateTimeImmutable($value) : $value);
        }

        return $this->expiresAt_;
    }

    public function issuedAt($value = null)
    {
        if (null !== $value) {
            $this->iat = \is_int($value) ?
                new \DateTimeImmutable(date(\DateTimeImmutable::ATOM, $value)) : (\is_string($value) ? new \DateTimeImmutable($value) : $value);
        }

        return $this->iat;
    }

    public function issuer($value = null)
    {
        if (null !== $value) {
            $this->iss = $value;
        }

        return $this->iss;
    }

    public function lastUsedAt($value = null)
    {
        if (null !== $value) {
            $this->last_used_at = \is_int($value) ?
                new \DateTimeImmutable(date(\DateTimeImmutable::ATOM, $value)) : (\is_string($value) ? new \DateTimeImmutable($value) : $value);
        }

        return $this->last_used_at;
    }

    public function revoked()
    {
        return $this->revoked;
    }

    public function markAsRevoked()
    {
        $this->revoked = true;

        return $this;
    }

    public function csrfToken(?string $value = null)
    {
        if (null !== $value) {
            $this->token_ = $value;
        }

        return $this->token_;
    }

    public function toArray()
    {
        return [
            'provider' => 'drewlabs:jwt',
            'id' => $this->subject(),
            'idToken' => $this->id(),
            'scopes' => $this->abilities(),
            'expiresAt' => ($date = $this->expiresAt()) instanceof DateTimeInterface ? $date->format(\DateTimeImmutable::ATOM) : $date,
            'iat' => ($iat = $this->issuedAt()) instanceof DateTimeInterface ? $iat->format(\DateTimeImmutable::ATOM) : $iat,
            'iss' => $this->issuer(),
        ];
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

    private function setClaimTypeValues(array $payload)
    {
        foreach ($payload as $key => $value) {
            if (ClaimTypes::EXPIRATION === $key) {
                $this->expiresAt($value);
                continue;
            }

            if (ClaimTypes::ISSUE_AT === $key) {
                $this->issuedAt($value);
                continue;
            }

            if (ClaimTypes::ISSUER === $key) {
                $this->issuer($value);
                continue;
            }

            if (ClaimTypes::JIT === $key) {
                $this->id($value);
                continue;
            }

            if (ClaimTypes::SCOPES === $key) {
                $this->abilities((array) $value);
                continue;
            }

            if (ClaimTypes::SUBJECT === $key) {
                $this->subject((string) $value);
                continue;
            }

            if (ClaimTypes::XCSRF === $key) {
                $this->csrfToken((string) $value);
                continue;
            }
        }
    }
}
