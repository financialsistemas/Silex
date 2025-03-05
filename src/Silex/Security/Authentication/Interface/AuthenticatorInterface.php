<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Interface;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use UnexpectedValueException;

interface AuthenticatorInterface extends AuthenticationEntryPointInterface
{
    public function supports(Request $request);

    /**
     *
     * @return mixed
     * @throws UnexpectedValueException
     */
    public function getCredentials(Request $request);

    /**
     *
     * @param mixed $credentials
     * @return UserInterface|null
     * @throws AuthenticationException
     */
    public function getUser($credentials, UserProviderInterface $userProvider);

    /**
     *
     * @param mixed $credentials
     * @return bool
     * @throws AuthenticationException
     */
    public function checkCredentials($credentials, UserInterface $user);

    /**
     *
     * @see AbstractGuardAuthenticator
     * @return GuardTokenInterface
     */
    public function createAuthenticatedToken(UserInterface $user, string $providerKey);

    /**
     *
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception);

    /**
     *
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey);

    /**
     *
     * @return bool
     */
    public function supportsRememberMe();
}