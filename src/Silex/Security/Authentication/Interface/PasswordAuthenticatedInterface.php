<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Interface;

interface PasswordAuthenticatedInterface
{
    /**
     *
     * @param mixed $credentials
     */
    public function getPassword($credentials): ?string;
}