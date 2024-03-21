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

use Drewlabs\Auth\Jwt\Contracts\JWTInterface;
use Drewlabs\Auth\Jwt\Exceptions\DecodeTokenException;
use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key as JWTKey;

class JWT implements JWTInterface
{
    /**
     * Algorithm de hashage du token.
     *
     * @var string
     */
    private $alg;

    /**
     * Private key of encoding key.
     *
     * @var string
     */
    private $encryptionKey;

    /**
     * Public key ised in decoding token.
     *
     * @var string
     */
    private $decryptionKey;

    /**
     * @param Key|AsymmetricKey|string $key
     *
     * @return self
     */
    public function __construct($key)
    {
        if (!\is_string($key) && !($key instanceof AsymmetricKey) && !($key instanceof Key)) {
            throw new \InvalidArgumentException('Expect key parameter to be of type '.AsymmetricKey::class.', '.Key::class.' or string got: '.(\is_object($key) && (null !== $key) ? $key::class : \gettype($key)));
        }
        if ($key instanceof AsymmetricKey) {
            return $this->configureForSSL($key);
        }

        $this->configureForHMAC($key);
    }

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array $payload PHP object or array
     *
     * @return string A signed JWT
     */
    public function encode($payload): ?string
    {
        return (string) FirebaseJWT::encode($payload, $this->encryptionKey, $this->alg);
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @return object The JWT's payload as a PHP object
     */
    public function decode($token): object
    {
        try {
            return (object) FirebaseJWT::decode($token, new JWTKey($this->decryptionKey, $this->alg));
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw new DecodeTokenException($e->getMessage());
        } catch (\Firebase\JWT\BeforeValidException $e) {
            throw new DecodeTokenException($e->getMessage());
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new DecodeTokenException($e->getMessage());
        } catch (\UnexpectedValueException $e) {
            throw new DecodeTokenException($e->getMessage());
        } catch (\Exception $e) {
            throw new DecodeTokenException($e->getMessage());
        }
    }

    private function configureForSSL(AsymmetricKey $key)
    {
        $this->alg = 'RS256';
        $this->encryptionKey = $key->privateKey();
        $this->decryptionKey = $key->publicKey();
    }

    /**
     * @param Key|string $key
     *
     * @return void
     */
    private function configureForHMAC($key)
    {
        $this->alg = 'HS256';
        $this->encryptionKey = (string) $key;
        $this->decryptionKey = (string) $key;
    }
}
