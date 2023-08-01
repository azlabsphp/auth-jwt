<?php

use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenRepository;
use Drewlabs\Auth\Jwt\Contracts\RevokedTokenStorageAdapter;

class RevokedTokenStorage implements RevokedTokenStorageAdapter
{
    /**
     * @var AccessTokenRepository
     */
    private $repository;

    /**
     * Create revoked token storage
     * 
     * @param AccessTokenRepository $repository 
     */
    public function __construct(AccessTokenRepository $repository)
    {
        $this->repository = $repository;
    }

    public function get($key)
    {
        return $this->repository->findById($key);
    }

    public function put(AccessTokenEntity $token)
    {
        $this->repository->persist($token->markAsRevoked());
    }

    public function has(AccessTokenEntity $value): bool
    {
        return null === ($value = $this->get($value->id())) ? false : $value->revoked();
    }

    public function flush()
    {
        return $this->repository->prune();
    }

}