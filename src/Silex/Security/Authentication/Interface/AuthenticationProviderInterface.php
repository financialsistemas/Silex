<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Interface;


use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

interface AuthenticationProviderInterface extends AuthenticationManagerInterface
{
    public const USERNAME_NONE_PROVIDED = 'NONE_PROVIDED';

    public function supports(TokenInterface $token);
}