<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Provider;

use Silex\Security\Authentication\Interface\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\LogicException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class RememberMeAuthenticationProvider implements AuthenticationProviderInterface
{
    private $userChecker;
    private $secret;
    private $providerKey;

    /**
     * @param UserCheckerInterface $userChecker
     * @param string $secret
     * @param string $providerKey
     */
    public function __construct(UserCheckerInterface $userChecker, string $secret, string $providerKey)
    {
        $this->userChecker = $userChecker;
        $this->secret = $secret;
        $this->providerKey = $providerKey;
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('The token is not supported by this authentication provider.');
        }

        if ($this->secret !== $token->getSecret()) {
            throw new BadCredentialsException('The presented secret does not match.');
        }

        $user = $token->getUser();

        if (!$user instanceof UserInterface) {
            throw new LogicException(sprintf('Method "%s::getUser()" must return a "%s" instance, "%s" returned.', get_debug_type($token), UserInterface::class, get_debug_type($user)));
        }

        $this->userChecker->checkPreAuth($user);
        $this->userChecker->checkPostAuth($user);

        $authenticatedToken = new RememberMeToken($user, $this->providerKey, $this->secret);
        $authenticatedToken->setAttributes($token->getAttributes());

        return $authenticatedToken;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof RememberMeToken && $token->getFirewallName() === $this->providerKey;
    }
}