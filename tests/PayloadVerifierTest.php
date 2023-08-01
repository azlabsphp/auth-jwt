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

use Drewlabs\Auth\Jwt\Payload\Claims;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\Jwt\Payload\PayloadFactory;
use Drewlabs\Auth\Jwt\Payload\PayloadVerifier;
use PHPUnit\Framework\TestCase;

class PayloadVerifierTest extends TestCase
{
    public function test_verify_failed()
    {
        $factory = new PayloadFactory($this->createClaims());
        $verifier = new PayloadVerifier($factory);
        $exp = (new \DateTimeImmutable())->add(\DateInterval::createFromDateString('1 day'));
        $this->assertFalse($verifier->verify([

            ClaimTypes::EXPIRATION => $exp,
            'sub' => 1,
            'scopes' => ['*'],
        ]));
    }

    public function test_verify()
    {
        $factory = new PayloadFactory($this->createClaims());
        $verifier = new PayloadVerifier($factory);
        $exp = (new \DateTimeImmutable())->add(\DateInterval::createFromDateString('1 day'));
        $payload = $factory->make([
            ClaimTypes::EXPIRATION => $exp,
            'sub' => 1,
            'scopes' => ['*'],
        ]);
        $this->assertTrue($verifier->verify($payload));
    }

    private function createClaims()
    {
        return new Claims('http://127.0.0.1');
    }
}
