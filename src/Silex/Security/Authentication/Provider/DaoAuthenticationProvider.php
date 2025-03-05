<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Provider;

use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\LegacyPasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class DaoAuthenticationProvider extends UserAuthenticationProvider
{
    private $hasherFactory;
    private $userProvider;

    /**
     * @param PasswordHasherFactoryInterface $hasherFactory
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, string $providerKey, $hasherFactory, bool $hideUserNotFoundExceptions = true)
    {
        parent::__construct($userChecker, $providerKey, $hideUserNotFoundExceptions);

        $this->hasherFactory = $hasherFactory;
        $this->userProvider = $userProvider;
    }

    /**
     * {@inheritdoc}
     */
    protected function checkAuthentication(UserInterface $user, UsernamePasswordToken $token)
    {
        $currentUser = $token->getUser();

        if (empty($currentUser)) {
            throw new BadCredentialsException('The presented password cannot be empty.');
        }

        if ($currentUser instanceof UserInterface) {
            if ($currentUser->getPassword() !== $user->getPassword()) {
                throw new BadCredentialsException('The credentials were changed from another session.');
            }
        } else {
            if (null === $user->getPassword()) {
                throw new BadCredentialsException('The presented password is invalid.');
            }
        }
    }

    protected function retrieveUser(string $userIdentifier, UsernamePasswordToken $token)
    {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByIdentifier($userIdentifier);

            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException('The user provider must return a UserInterface object.');
            }

            return $user;
        } catch (UserNotFoundException $e) {
            $e->setUserIdentifier($userIdentifier);
            throw $e;
        } catch (\Exception $e) {
            $e = new AuthenticationServiceException($e->getMessage(), 0, $e);
            $e->setToken($token);
            throw $e;
        }
    }
}