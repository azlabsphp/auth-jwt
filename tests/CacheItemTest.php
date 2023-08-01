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

use Drewlabs\Auth\Jwt\CacheItem;
use PHPUnit\Framework\TestCase;

class CacheItemTest extends TestCase
{
    public function test_expires_method_for_expiration_equals_null()
    {
        $item = new CacheItem(new \stdClass());
        $this->assertFalse($item->hasExpires(), 'Expect hasExpires() method to return false if null is passed expiration ]');
    }

    public function test_to_array_method()
    {
        $item = new CacheItem(new \stdClass());
        $this->assertIsArray($item->toArray());
        $this->assertNull($item->toArray()['expires_at']);
    }

    public function test_expires_method()
    {
        $item = new CacheItem(new \stdClass(), -60);
        $this->assertTrue($item->hasExpires());
    }
}
