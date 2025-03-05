<?php

declare(strict_types=1);

namespace Silex\Security\Authentication;


use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

use function is_array;

class AnonymousToken extends AbstractToken
{
    private $secret;

    /**
     * @param string $secret
     * @param string|UserInterface $user
     * @param string[] $roles
     */
    public function __construct(string $secret, $user, array $roles = [])
    {
        parent::__construct($roles);

        $this->secret = $secret;
        $this->setUser($user);
        $this->setAuthenticated(true, false);
    }

    public function getCredentials()
    {
        return '';
    }

    /**
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    public function __serialize(): array
    {
        return [$this->secret, parent::__serialize()];
    }

    public function __unserialize(array $data): void
    {
        [$this->secret, $parentData] = $data;
        $parentData = is_array($parentData) ? $parentData : unserialize($parentData);
        parent::__unserialize($parentData);
    }
}