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

use Drewlabs\Auth\Jwt\Exceptions\InvalidKeyFileException;
use Drewlabs\Auth\Jwt\Exceptions\MissingEncryptionFileException;

class AsymmetricKey
{
    /**
     * Private key value.
     *
     * @var \OpenSSLAsymmetricKey|resource
     */
    private $private;

    /**
     * Public part of the asymmertric key.
     *
     * @var string
     */
    private $public;

    public function __construct($key, $publicKey)
    {
        $this->private = $key;
        $this->public = $publicKey;
    }

    public static function loadFromFile(string $path, ?string $passphrase = '')
    {
        if (file_exists($path)) {
            $privateKey = openssl_pkey_get_private(
                file_get_contents($path),
                $passphrase ?? ''
            );
            if (false === $privateKey) {
                throw new InvalidKeyFileException($path);
            }

            return new self($privateKey, openssl_pkey_get_details($privateKey)['key']);
        }
        throw new MissingEncryptionFileException($path);
    }

    public function toArray()
    {
        return [$this->private, $this->public];
    }

    public function privateKey()
    {
        return $this->private;
    }

    public function publicKey()
    {
        return $this->public;
    }
}
