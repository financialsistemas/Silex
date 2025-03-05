<?php

namespace Silex\Security\Authentication\Interface;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

interface AuthenticationManagerInterface
{
    public function authenticate(TokenInterface $token);
}