<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\EntryPoint;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class BasicAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    private $realmName;

    public function __construct(string $realmName)
    {
        $this->realmName = $realmName;
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $response = new Response();
        $response->headers->set('WWW-Authenticate', sprintf('Basic realm="%s"', $this->realmName));
        $response->setStatusCode(401);

        return $response;
    }
}