<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Provider;

use InvalidArgumentException;
use Silex\Security\Authentication\Interface\AuthenticationProviderInterface;
use Silex\Security\Authentication\Interface\GuardTokenInterface;
use Silex\Security\Authentication\Interface\PasswordAuthenticatedInterface;
use Silex\Security\Guard\Token\PreAuthenticationGuardToken;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationExpiredException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use TypeError;
use UnexpectedValueException;

class GuardAuthenticationProvider implements AuthenticationProviderInterface
{
    private $guardAuthenticators;
    private $userProvider;
    private $providerKey;
    private $userChecker;
    private $passwordHasher;

    public function __construct(iterable $guardAuthenticators, UserProviderInterface $userProvider, string $providerKey, UserCheckerInterface $userChecker, $passwordHasher = null)
    {
        $this->guardAuthenticators = $guardAuthenticators;
        $this->userProvider = $userProvider;
        $this->providerKey = $providerKey;
        $this->userChecker = $userChecker;
        $this->passwordHasher = $passwordHasher;
    }

    /**
     *
     * @param GuardTokenInterface $token
     * @return TokenInterface
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$token instanceof GuardTokenInterface) {
            throw new InvalidArgumentException('GuardAuthenticationProvider only supports GuardTokenInterface.');
        }

        if (!$token instanceof PreAuthenticationGuardToken) {
            if ($token->getUser()) {
                return $token;
            }

            throw new AuthenticationExpiredException();
        }

        $guardAuthenticator = $this->findOriginatingAuthenticator($token);

        if (null === $guardAuthenticator) {
            throw new AuthenticationException(sprintf('Token with provider key "%s" did not originate from any of the guard authenticators of provider "%s".', $token->getGuardProviderKey(), $this->providerKey));
        }

        return $this->authenticateViaGuard($guardAuthenticator, $token);
    }

    private function authenticateViaGuard($guardAuthenticator, $token): TokenInterface|GuardTokenInterface
    {
        $user = $guardAuthenticator->getUser($token->getCredentials(), $this->userProvider);

        if (null === $user) {
            $e = new UserNotFoundException(sprintf('Null returned from "%s::getUser()".', get_debug_type($guardAuthenticator)));
            $e->setUserIdentifier($token->getUserIdentifier());

            throw $e;
        }

        if (!$user instanceof UserInterface) {
            throw new UnexpectedValueException(sprintf('The "%s::getUser()" method must return a UserInterface. You returned "%s".', get_debug_type($guardAuthenticator), get_debug_type($user)));
        }

        if ($guardAuthenticator instanceof PasswordAuthenticatedInterface && !$user instanceof PasswordAuthenticatedUserInterface) {
            trigger_deprecation('symfony/security-guard', '5.3', 'Not implementing the "%s" interface in class "%s" while using password-based guard authenticators is deprecated.', PasswordAuthenticatedUserInterface::class, get_debug_type($user));
        }

        $this->userChecker->checkPreAuth($user);
        if (true !== $checkCredentialsResult = $guardAuthenticator->checkCredentials($token->getCredentials(), $user)) {
            if (false !== $checkCredentialsResult) {
                throw new TypeError(sprintf('"%s::checkCredentials()" must return a boolean value.', get_debug_type($guardAuthenticator)));
            }

            throw new BadCredentialsException(sprintf('Authentication failed because "%s::checkCredentials()" did not return true.', get_debug_type($guardAuthenticator)));
        }
        if ($this->userProvider instanceof PasswordUpgraderInterface && $guardAuthenticator instanceof PasswordAuthenticatedInterface && null !== $this->passwordHasher && (null !== $password = $guardAuthenticator->getPassword($token->getCredentials())) && $this->passwordHasher->needsRehash($user)) {
            if ($this->passwordHasher instanceof UserPasswordHasherInterface) {
                $this->userProvider->upgradePassword($user, $this->passwordHasher->hashPassword($user, $password));
            }
        }
        $this->userChecker->checkPostAuth($user);

        $authenticatedToken = $guardAuthenticator->createAuthenticatedToken($user, $this->providerKey);
        if (!$authenticatedToken instanceof TokenInterface) {
            throw new UnexpectedValueException(sprintf('The "%s::createAuthenticatedToken()" method must return a TokenInterface. You returned "%s".', get_debug_type($guardAuthenticator), get_debug_type($authenticatedToken)));
        }

        return $authenticatedToken;
    }

    private function findOriginatingAuthenticator(PreAuthenticationGuardToken $token)
    {
        foreach ($this->guardAuthenticators as $key => $guardAuthenticator) {
            $uniqueGuardKey = $this->providerKey.'_'.$key;

            if ($uniqueGuardKey === $token->getGuardProviderKey()) {
                return $guardAuthenticator;
            }
        }

        return null;
    }

    public function supports(TokenInterface $token)
    {
        if ($token instanceof PreAuthenticationGuardToken) {
            return null !== $this->findOriginatingAuthenticator($token);
        }

        return $token instanceof GuardTokenInterface;
    }
}