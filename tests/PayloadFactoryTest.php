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

use Drewlabs\Auth\Jwt\Contracts\PayloadFactoryInterface;
use Drewlabs\Auth\Jwt\Payload\Claims;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\Jwt\Payload\PayloadFactory;
use Drewlabs\Core\Helpers\DateTime;
use PHPUnit\Framework\TestCase;

class PayloadFactoryTest extends TestCase
{
    public function test_contructor()
    {
        $this->assertInstanceOf(PayloadFactoryInterface::class, new PayloadFactory($this->createClaims()));
    }

    public function test_set_TTL()
    {
        $factory = new PayloadFactory($this->createClaims());
        $factory = $factory->setPayloadTTL(60);
        $this->assertSame(60, $factory->getClaims()->getTTL());
    }

    public function test_make_payload()
    {
        $factory = new PayloadFactory($this->createClaims());
        $exp = (new \DateTimeImmutable())->add(\DateInterval::createFromDateString('1 day'));
        $payload = $factory->make([
            ClaimTypes::EXPIRATION => $exp,
            'sub' => 1,
            'scopes' => ['*'],
        ]);
        $this->assertSame(1, $payload['sub']);
        $this->assertSame(['*'], $payload['scopes']);
        $this->assertTrue(in_array(ClaimTypes::JIT, array_keys($payload), true));
        $this->assertSame($exp->getTimestamp(), $payload[ClaimTypes::EXPIRATION]);
        $this->assertSame((new \DateTimeImmutable())->getTimestamp(), $payload[ClaimTypes::NOT_BEFORE]);
        $this->assertTrue(DateTime::isfuture(\DateTimeImmutable::createFromFormat('Y-m-d H:i:s', date('Y-m-d H:i:s', $payload[ClaimTypes::EXPIRATION]))));
    }

    private function createClaims()
    {
        return new Claims('http://127.0.0.1');
    }
}
