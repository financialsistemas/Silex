<?php

declare(strict_types=1);

namespace Silex\Security\Authentication;

use Exception;
use InvalidArgumentException;
use Silex\Security\Authentication\Interface\AuthenticationManagerInterface;
use Silex\Security\Authentication\Interface\AuthenticationProviderInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\AuthenticationEvents;
use Symfony\Component\Security\Core\Event\AuthenticationSuccessEvent;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\ProviderNotFoundException;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class_exists(AuthenticationEvents::class);
class_exists(AuthenticationSuccessEvent::class);
class AuthenticationProviderManager implements AuthenticationManagerInterface
{
    private $providers;
    private $eraseCredentials;
    private $eventDispatcher;

    public function __construct(iterable $providers, bool $eraseCredentials = true)
    {
        if (empty($providers)) {
            throw new InvalidArgumentException('You must at least add one authentication provider.');
        }

        $this->providers = $providers;
        $this->eraseCredentials = $eraseCredentials;
    }

    public function setEventDispatcher(EventDispatcherInterface $dispatcher): void
    {
        $this->eventDispatcher = $dispatcher;
    }

    /**
     * @throws Exception
     */
    public function authenticate(TokenInterface $token)
    {
        $lastException = null;
        $result = null;

        foreach ($this->providers as $provider) {
            if (!$provider instanceof AuthenticationProviderInterface) {
                throw new InvalidArgumentException(sprintf('Provider "%s" must implement the AuthenticationProviderInterface.', get_debug_type($provider)));
            }

            if (!$provider->supports($token)) {
                continue;
            }

            try {
                $result = $provider->authenticate($token);

                if ($result !== null) {
                    break;
                }
            } catch (AuthenticationException $e) {
                $lastException = $e;
            } catch (Exception $e) {
                $lastException = new BadCredentialsException('Bad credentials.', 0, $e);
            }
        }

        // Se a autenticação foi bem-sucedida
        if (null !== $result) {
            if ($this->eraseCredentials) {
                $result->eraseCredentials();
            }

            if ($this->eventDispatcher) {
                $this->eventDispatcher->dispatch(new AuthenticationSuccessEvent($result), AuthenticationEvents::AUTHENTICATION_SUCCESS);
            }

            return $result;
        }

        if (null === $lastException) {
            $lastException = new ProviderNotFoundException();
        }

        if ($this->eventDispatcher) {
            $this->onAuthenticationFailure(new Request(), $lastException);
        }

        throw $lastException;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($exception instanceof BadCredentialsException) {
            return new JsonResponse(['status' => 'error', 'message' => 'Invalid credentials'], 401);
        }
        return new JsonResponse(['status' => 'error', 'message' => 'Authentication failed'], 403);
    }
}