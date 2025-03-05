<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Provider;

use InvalidArgumentException;
use Silex\Security\Authentication\Interface\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

abstract class UserAuthenticationProvider implements AuthenticationProviderInterface
{
    private $hideUserNotFoundExceptions;
    private $userChecker;
    private $providerKey;

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(UserCheckerInterface $userChecker, string $providerKey, bool $hideUserNotFoundExceptions = true)
    {
        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('The token is not supported by this authentication provider.');
        }

        $username = method_exists($token, 'getUserIdentifier') ? $token->getUserIdentifier() : $token->getUsername();
        if ('' === $username || null === $username) {
            $username = AuthenticationProviderInterface::USERNAME_NONE_PROVIDED;
        }

        try {
            $user = $this->retrieveUser($username, $token);
        } catch (UserNotFoundException $e) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials.', 0, $e);
            }
            $e->setUserIdentifier($username);

            throw $e;
        }

        if (!$user instanceof UserInterface) {
            throw new AuthenticationServiceException('retrieveUser() must return a UserInterface.');
        }

        try {
            $this->userChecker->checkPreAuth($user);
            $this->checkAuthentication($user, $token);
            $this->userChecker->checkPostAuth($user);
        } catch (AccountStatusException|BadCredentialsException $e) {
            if ($this->hideUserNotFoundExceptions && !$e instanceof CustomUserMessageAccountStatusException) {
                throw new BadCredentialsException('Bad credentials.', 0, $e);
            }

            throw $e;
        }

        if ($token instanceof SwitchUserToken) {
            $roles = $user->getRoles();
            $roles[] = 'ROLE_PREVIOUS_ADMIN';

            $authenticatedToken = new SwitchUserToken($user, $token->getFirewallName(), $this->providerKey, $roles, $token->getOriginalToken());
        } else {
            $authenticatedToken = new UsernamePasswordToken($user, $this->providerKey, $user->getRoles());
        }

        $authenticatedToken->setAttributes($token->getAttributes());

        return $authenticatedToken;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken && $this->providerKey === $token->getFirewallName();
    }

    /**
     *
     * @return UserInterface
     * @throws AuthenticationException if the credentials could not be validated
     */
    abstract protected function retrieveUser(string $username, UsernamePasswordToken $token);

    /**
     *
     * @throws AuthenticationException if the credentials could not be validated
     */
    abstract protected function checkAuthentication(UserInterface $user, UsernamePasswordToken $token);
}