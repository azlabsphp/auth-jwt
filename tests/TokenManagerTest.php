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

use Drewlabs\Core\Helpers\Str;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\Jwt\Factory;
use Drewlabs\Auth\Jwt\NewAccessToken;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use PHPUnit\Framework\TestCase;

class TokenManagerTest extends TestCase
{
    public function test_constructor()
    {
        $this->assertInstanceOf(TokenManagerInterface::class, $this->createManager());
    }

    public function test_create_token()
    {
        $token = $this->createManager()->createToken([
            ClaimTypes::SUBJECT => 1,
            ClaimTypes::SCOPES => ['*'],
        ]);

        $this->assertInstanceOf(NewAccessToken::class, $token);
        $this->assertIsString($token->plainTextToken);
    }

    public function test_access_token_instanceof_access_token_entity()
    {
        $token = $this->createManager()->createToken([
            ClaimTypes::SUBJECT => 1,
            ClaimTypes::SCOPES => ['*'],
        ]);
        $this->assertInstanceOf(AccessTokenEntity::class, $token->accessToken);
    }

    public function test_new_access_token_can()
    {
        $token = $this->createManager()->createToken([
            ClaimTypes::SUBJECT => 1,
            ClaimTypes::SCOPES => ['*'],
        ]);
        $this->assertTrue($token->can('create-user'));
    }

    public function test_new_access_token_revoke()
    {
        $token = $this->createManager()->createToken([
            ClaimTypes::SUBJECT => 1,
            ClaimTypes::SCOPES => ['*'],
        ]);
        $this->assertTrue($token->revoke());
    }

    public function test_revoke_token()
    {
        $manager = $this->createManager();
        $token = $manager->createToken([
            ClaimTypes::SUBJECT => 1,
            ClaimTypes::SCOPES => ['*'],
        ]);
        $manager->revokeToken($token->plainTextToken);
        $this->assertTrue($manager->isRevoked($token->accessToken));
    }

    private function createManager()
    {
        $config = [
            'storage' => [
                'revokeTokens' => 'array',
            ],

            'accessToken' => [
                'refreshTTL' => 10000,
                'tokenTTL' => 360,
            ],

            'issuer' => 'MyApplication',

            'use_ssl' => true,

            'encryption' => [
                'default' => [
                    'key' => Str::base62encode(random_bytes(32))
                ],
            ],
        ];
        return (new Factory)->create($config);
    }
}
