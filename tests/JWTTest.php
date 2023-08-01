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

use Drewlabs\Auth\Jwt\Providers\JWT;
use Drewlabs\Auth\Jwt\Providers\KeyFactory;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    public function test_encode()
    {
        $jwt = new JWT('HS256', 'secret');
        $token = $jwt->encode([
            'name' => 'Azandrew',
            'address' => 'HN 238, LOME',
        ]);
        $this->assertIsString($token, 'Expect the jwt::encode() method to return a token string');
    }

    public function test_decode()
    {
        $jwt = new JWT('HS256', 'secret');
        $token = $jwt->encode([
            'name' => 'Azandrew',
            'address' => 'HN 238, LOME',
        ]);
        $this->assertSame(
            ['name' => 'Azandrew', 'address' => 'HN 238, LOME'],
            get_object_vars($jwt->decode($token)),
            'Expect calling $jwt::decode() on generated token to return the same payload'
        );
    }

    public function test_public_private_key_file()
    {
        $jwt = new JWT('RS256', KeyFactory::create([
            'encryption' => [
                'ssl' => [
                    'key' => __DIR__.'/storage/.ssh/id_rsa',
                    'public' => null,
                    'passphrase' => '',
                ],
            ],
        ]));
        $token = $jwt->encode([
            'name' => 'Azandrew',
            'address' => 'HN 238, LOME',
        ]);
        $this->assertIsString($token, 'Expect the jwt::encode() method to return a token string');
        $this->assertSame(
            ['name' => 'Azandrew', 'address' => 'HN 238, LOME'],
            get_object_vars($jwt->decode($token)),
            'Expect calling $jwt::decode() on generated token to return the same payload'
        );
    }

    public function test_public_private_key_pair()
    {
        $key = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
EOD;
        $publicKey = <<<EOT
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs+XO5jg2oVct6gSsDbOJ
M6s3XE1DFFvAR32g1CLBQnP9afpGoYGWhaYNVOpOmgFtoB8eBZEcrZ83+Ui3m4aT
sW6wFHz7MgsYk9cIeAOL1ptgO2yQuNI/8/TfJkW2kn7l31aAyzAltkXwxlDFK0d8
VLD3HCpSmZzvinznLBMS7AOyxNlUWa7fby1clcbu0xDrEodLUdG83xvnHEMN16kK
hMsUHWorC61w56BeuH91Lp5zW28GQ/RmeAJ9aGGSxpNokbNND+dAXRo/R7k4upua
LZo09Ap6oR6lFvtzWnjU+8tcvqgs6oHRBteLiDsu9slLIpfZJXN84Kqp5/I1GiCx
2EHjc8Hpb0dRAORL7XH+VRleNecWaT0d5r9eN28im8FPrmBdE4spze+P1xNjtXWr
aJbSbYvsFvSxXQVQIw7AC9kGnE3lF+CjXrHuPxGwaP66XFfYfd8XvkT0Sfnm68Iq
9SJO+uICyCtni/kfe9VgSuBjPtUgsR4pkB2FJo8StbuRAgMBAAE=
-----END PUBLIC KEY-----
EOT;

        $jwt = new JWT('RS256', KeyFactory::create([
            'encryption' => [
                'ssl' => [
                    'key' => $key,
                    'public' => $publicKey,
                    'passphrase' => 'hello',
                ],
            ],
        ]));
        $token = $jwt->encode([
            'name' => 'Azandrew',
            'address' => 'HN 238, LOME',
        ]);
        $this->assertIsString($token, 'Expect the jwt::encode() method to return a token string');
        $this->assertSame(
            ['name' => 'Azandrew', 'address' => 'HN 238, LOME'],
            get_object_vars($jwt->decode($token)),
            'Expect calling $jwt::decode() on generated token to return the same payload'
        );
    }
}
