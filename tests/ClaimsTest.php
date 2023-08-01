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

use Drewlabs\Contracts\Jwt\ClaimsInterface;
use Drewlabs\Auth\Jwt\Payload\Claims;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use PHPUnit\Framework\TestCase;

class ClaimsTest extends TestCase
{
    public function test_claims_constructor()
    {
        $claims = new Claims('http://127.0.0.1');
        $this->assertInstanceOf(ClaimsInterface::class, $claims);
        $this->assertSame('http://127.0.0.1', $claims->getiss());
    }

    public function test_set_class_ttl()
    {
        $claims = new Claims('http:127.0.0.1');
        $this->assertSame(360, $claims->getTTL());
        $claims = $claims->setTTL(30);
        $this->assertNotSame(360, $claims->getTTL());
        $this->assertSame(30, $claims->getTTL());
    }

    public function test_to_payload()
    {
        $claims = new Claims('http:127.0.0.1');

        $exp = (new \DateTimeImmutable())->add(\DateInterval::createFromDateString('1 day'));

        $payload = $claims->toPayload([
            ClaimTypes::EXPIRATION => $exp,
            'sub' => 1,
            'scopes' => ['*'],
        ]);
        $this->assertSame(1, $payload['sub']);
        $this->assertSame(['*'], $payload['scopes']);
        $this->assertTrue(\in_array(ClaimTypes::JIT, array_keys($payload), true));
        $this->assertSame($exp->getTimestamp(), $payload[ClaimTypes::EXPIRATION]);
        $this->assertSame((new \DateTimeImmutable())->getTimestamp(), $payload[ClaimTypes::NOT_BEFORE]);
    }
}
