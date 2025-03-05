<?php

declare(strict_types=1);

namespace Silex\Security\Guard\Token;

use LogicException;
use Silex\Security\Authentication\Interface\GuardTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class PreAuthenticationGuardToken extends AbstractToken implements GuardTokenInterface
{
    private $credentials;
    private $guardProviderKey;

    public function __construct($credentials, string $guardProviderKey)
    {
        $this->credentials = $credentials;
        $this->guardProviderKey = $guardProviderKey;

        parent::__construct();
    }

    public function getGuardProviderKey()
    {
        return $this->guardProviderKey;
    }

    public function getCredentials()
    {
        return $this->credentials;
    }

    /**
     * @param bool $authenticated
     * @return void
     */
    public function setAuthenticated(bool $authenticated)
    {
        if ($authenticated) {
            throw new LogicException('The PreAuthenticationGuardToken is *never* authenticated.');
        }
    }
}