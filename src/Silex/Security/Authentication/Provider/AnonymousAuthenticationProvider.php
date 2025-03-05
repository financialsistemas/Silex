<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Provider;

use Silex\Security\Authentication\AnonymousToken;
use Silex\Security\Authentication\Interface\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class AnonymousAuthenticationProvider implements AuthenticationProviderInterface
{
    private $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    public function supports(?TokenInterface $token): ?bool
    {
        return $token instanceof AnonymousToken;
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('The token is not supported by this authentication provider.');
        }

        if ($this->secret !== $token->getSecret()) {
            throw new BadCredentialsException('The token secret is invalid.');
        }

        return $token;
    }
}