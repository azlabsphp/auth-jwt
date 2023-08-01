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

namespace Drewlabs\Auth\Jwt\Providers;

use Drewlabs\Core\Helpers\Str;

class Key
{
    /**
     * @var string
     */
    private $value;

    public function __construct(string $key)
    {
        $this->value = Str::startsWith($key, 'base64:') ? base64_decode(Str::after('base64:', $key), true) : $key;
    }

    /**
     * String representation of the encryption key.
     *
     * @return string
     */
    public function __toString()
    {
        return "$this->value";
    }
}
