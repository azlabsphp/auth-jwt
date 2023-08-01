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

namespace Drewlabs\Auth\Jwt\Providers;

use Drewlabs\Auth\Jwt\Exceptions\InvalidKeyFileException;
use Drewlabs\Auth\Jwt\Exceptions\MissingEncryptionFileException;

class KeyFactory
{
    /**
     * @throws InvalidKeyFileException
     * @throws MissingEncryptionFileException
     *
     * @return AsymmetricKey|Key
     */
    public static function create(array $config = [])
    {
        // ssl encrypt have precedence over the default HS256 encryption algorithm
        if (isset($config['encryption']['ssl']['key'])) {
            $key =  $config['encryption']['ssl']['key'];
            if (\is_string($key) && file_exists($key)) {
                return AsymmetricKey::loadFromFile($key, $config['encryption']['ssl']['passphrase']);
            }
            if (\is_string($key) && \is_string($public = $config['encryption']['ssl']['public'])) {
                return new AsymmetricKey(trim($key), trim($public));
            }
        } else {
            return new Key($config['encryption']['default']['key']);
        }
    }
}
