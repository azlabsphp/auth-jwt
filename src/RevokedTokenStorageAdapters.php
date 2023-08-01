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

namespace Drewlabs\Auth\Jwt;

use Drewlabs\Auth\Jwt\Contracts\RevokedTokenStorageAdapter;

class RevokedTokenStorageAdapters
{
    /**
     * @var array<string, RevokedTokenStorageAdapter>
     */
    private $adapters = [];

    /**
     * Default adapter name.
     *
     * @var string
     */
    private $default = 'array';

    /**
     * @var self
     */
    private static $instance = null;

    /**
     * Creates a singleton object by making the constructor private.
     *
     * @return self
     */
    private function __construct()
    {
        $this->configureDefaults();
    }

    public static function getInstance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function configure(array $adapters)
    {
        foreach ($adapters as $key => $value) {
            $this->addAdapter($key, $value);
        }
    }

    /**
     * @return self
     */
    public function addAdapter(string $name, RevokedTokenStorageAdapter $adapter)
    {
        $this->adapters[$name] = $adapter;

        return $this;
    }

    /**
     * @param string $name
     *
     * @return RevokedTokenStorageAdapter
     */
    public function adapt(?string $name = null)
    {
        return $this->adapters[$name ?? $this->default] ?? new ArrayStorageAdapter();
    }

    /**
     * Default adapter setter and getter.
     *
     * @return RevokedTokenStorageAdapter
     */
    public function default(?string $name = null)
    {
        if (null !== $name) {
            $this->default = $name;
        }

        return $this->adapt($this->default);
    }

    private function configureDefaults()
    {
        $this->configure([
            'array' => new ArrayStorageAdapter(),
        ]);
        $this->default('array');
    }
}
