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

use Drewlabs\Auth\Jwt\AccessToken;
use Drewlabs\Auth\Jwt\Payload\Claims;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\Jwt\Payload\PayloadFactory;
use Drewlabs\Contracts\OAuth\Token;
use PHPUnit\Framework\TestCase;

class PersonalAccessTokenTest extends TestCase
{
    public function createPayload()
    {
        $factory = new PayloadFactory(new Claims('https://127.0.0.1'));
        $exp = (new \DateTimeImmutable())->add(\DateInterval::createFromDateString('1 day'));

        return $factory->make([
            ClaimTypes::EXPIRATION => $exp,
            'sub' => 1,
            'scopes' => ['*'],
        ]);
    }

    public function test_constructor()
    {
        $pat = new AccessToken($this->createPayload());
        $this->assertInstanceOf(Token::class, $pat);
    }

    public function test_abilities()
    {
        $pat = new AccessToken($this->createPayload());
        $this->assertSame(['*'], $pat->abilities());
    }

    public function test_can()
    {
        $pat = new AccessToken($this->createPayload());
        $this->assertTrue($pat->can('create-users'));
    }

    public function test_subject_getter_setters()
    {
        $pat = new AccessToken($this->createPayload());
        $pat->subject('UUID-08248-824082-8924');
        $this->assertSame('UUID-08248-824082-8924', $pat->subject());
    }

    public function test_default_claims_values()
    {
        $payload = $this->createPayload();
        $pat = new AccessToken($payload);
        $this->assertSame($payload[ClaimTypes::ISSUER], $pat->issuer());
        $this->assertSame(\DateTimeImmutable::createFromFormat(\DateTimeImmutable::ATOM, date(\DateTimeImmutable::ATOM, $payload[ClaimTypes::ISSUE_AT]))->getTimestamp(), $pat->issuedAt()->getTimestamp());
        $this->assertSame(\DateTimeImmutable::createFromFormat(\DateTimeImmutable::ATOM, date(\DateTime::ATOM, $payload[ClaimTypes::EXPIRATION]))->getTimestamp(), $pat->expiresAt()->getTimestamp());
        $this->assertSame($payload[ClaimTypes::JIT], $pat->id());
    }
}
