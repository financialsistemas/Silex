<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Listener\Firewall;

use Psr\Log\LoggerInterface;
use Silex\Security\Authentication\AnonymousToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\AbstractListener;

class AnonymousAuthenticationListener extends AbstractListener
{
    private $tokenStorage;
    private $secret;
    private $authenticationManager;
    private $logger;

    public function __construct(TokenStorageInterface $tokenStorage, string $secret, ?LoggerInterface $logger = null, $authenticationManager = null)
    {
        $this->tokenStorage = $tokenStorage;
        $this->secret = $secret;
        $this->authenticationManager = $authenticationManager;
        $this->logger = $logger;
    }

    public function supports(Request $request): ?bool
    {
        return null;
    }

    public function authenticate(RequestEvent $event)
    {
        if (null !== $this->tokenStorage->getToken()) {
            return;
        }

        try {
            $token = new AnonymousToken($this->secret, 'anon.', []);
            if (null !== $this->authenticationManager) {
                $token = $this->authenticationManager->authenticate($token);
            }

            $this->tokenStorage->setToken($token);

            $this->logger?->info('Populated the TokenStorage with an anonymous Token.');
        } catch (AuthenticationException $failed) {
            $this->logger?->info('Anonymous authentication failed.', ['exception' => $failed]);
        }
    }
}