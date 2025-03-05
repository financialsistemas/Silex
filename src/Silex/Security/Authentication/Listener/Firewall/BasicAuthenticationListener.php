<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Listener\Firewall;

use Exception;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Silex\Security\Authentication\AuthenticationProviderManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class BasicAuthenticationListener  extends AbstractListener
{
    private $tokenStorage;
    private $authenticationManager;
    private $providerKey;
    private $authenticationEntryPoint;
    private $logger;
    private $ignoreFailure;
    private $sessionStrategy;

    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationProviderManager $authenticationManager, string $providerKey, AuthenticationEntryPointInterface $authenticationEntryPoint, ?LoggerInterface $logger = null)
    {
        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->logger = $logger;
        $this->ignoreFailure = false;
    }

    public function supports(Request $request): ?bool
    {
        return null !== $request->headers->get('PHP_AUTH_USER');
    }

    public function authenticate(RequestEvent $event): void
    {
        $request = $event->getRequest();

        if (null === $username = $request->headers->get('PHP_AUTH_USER')) {
            return;
        }

        if (null !== $token = $this->tokenStorage->getToken()) {
            if ($token instanceof UsernamePasswordToken && $token->isAuthenticated(false) && $token->getUserIdentifier() === $username) {
                return;
            }
        }

        $this->logger?->info('Basic authentication Authorization header found for user.', ['username' => $username]);

        try {
            $previousToken = $token;

            $user = new InMemoryUser($username, $request->headers->get('PHP_AUTH_PW'));

            $token = $this->authenticationManager->authenticate(new UsernamePasswordToken($user, $request->headers->get('PHP_AUTH_PW'), [$this->providerKey]));

            $this->migrateSession($request, $token, $previousToken);

            $this->tokenStorage->setToken($token);
        } catch (AuthenticationException $e) {
            $token = $this->tokenStorage->getToken();
            if ($token instanceof UsernamePasswordToken && $this->providerKey === $token->getFirewallName()) {
                $this->tokenStorage->setToken();
            }

            $this->logger?->info('Basic authentication failed for user.', ['username' => $username, 'exception' => $e]);

            if ($this->ignoreFailure) {
                return;
            }

            $event->setResponse($this->authenticationEntryPoint->start($request, $e));
        } catch (Exception $e) {
            $this->logger?->error('Basic authentication failed for user.', ['username' => $username, 'exception' => $e]);

            $event->setResponse($this->authenticationEntryPoint->start($request, new AuthenticationException('Basic authentication failed.', 0, $e)));
        }
    }

    public function setSessionAuthenticationStrategy(SessionAuthenticationStrategyInterface $sessionStrategy)
    {
        $this->sessionStrategy = $sessionStrategy;
    }

    private function migrateSession(Request $request, TokenInterface $token, ?TokenInterface $previousToken)
    {
        if (!$this->sessionStrategy || !$request->hasSession() || !$request->hasPreviousSession()) {
            return;
        }

        if ($previousToken) {
            $user = $token->getUserIdentifier();
            $previousUser = $previousToken->getUserIdentifier();

            if ('' !== ($user ?? '') && $user === $previousUser) {
                return;
            }
        }

        $this->sessionStrategy->onAuthentication($request, $token);
    }
}