<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Listener\Firewall;

use Countable;
use InvalidArgumentException;
use LogicException;
use Psr\Log\LoggerInterface;
use Silex\Security\Guard\Token\PreAuthenticationGuardToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Silex\Security\Authentication\Storage\TokenStorageInterface;
use Silex\Security\Authentication\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use UnexpectedValueException;
use function count;
use function get_class;
use function is_array;

class GuardAuthenticationListener extends AbstractListener
{
    private $guardHandler;
    private $authenticationManager;
    private $providerKey;
    private $guardAuthenticators;
    private $logger;
    private $rememberMeServices;
    private $hideUserNotFoundExceptions;
    private $tokenStorage;

    public function __construct($guardHandler, /*AuthenticationManagerInterface*/ $authenticationManager, string $providerKey, iterable $guardAuthenticators, ?LoggerInterface $logger = null, bool $hideUserNotFoundExceptions = true, ?TokenStorageInterface $tokenStorage = null)
    {
        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->guardHandler = $guardHandler;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->guardAuthenticators = $guardAuthenticators;
        $this->logger = $logger;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->tokenStorage = $tokenStorage;
    }

    public function supports(Request $request): ?bool
    {
        if (null !== $this->logger) {
            $context = ['firewall_key' => $this->providerKey];

            if ($this->guardAuthenticators instanceof Countable || is_array($this->guardAuthenticators)) {
                $context['authenticators'] = count($this->guardAuthenticators);
            }

            $this->logger->debug('Checking for guard authentication credentials.', $context);
        }

        $guardAuthenticators = [];

        foreach ($this->guardAuthenticators as $key => $guardAuthenticator) {
            $this->logger?->debug('Checking support on guard authenticator.', ['firewall_key' => $this->providerKey, 'authenticator' => get_class($guardAuthenticator)]);

            if ($guardAuthenticator->supports($request)) {
                $guardAuthenticators[$key] = $guardAuthenticator;
            } elseif (null !== $this->logger) {
                $this->logger->debug('Guard authenticator does not support the request.', ['firewall_key' => $this->providerKey, 'authenticator' => get_class($guardAuthenticator)]);
            }
        }

        if (!$guardAuthenticators) {
            return false;
        }

        $request->attributes->set('_guard_authenticators', $guardAuthenticators);

        return true;
    }

    public function authenticate(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $guardAuthenticators = $request->attributes->get('_guard_authenticators');
        $request->attributes->remove('_guard_authenticators');

        foreach ($guardAuthenticators as $key => $guardAuthenticator) {
            $uniqueGuardKey = $this->providerKey.'_'.$key;

            $this->executeGuardAuthenticator($uniqueGuardKey, $guardAuthenticator, $event);

            if ($event->hasResponse()) {
                $this->logger?->debug('The "{authenticator}" authenticator set the response. Any later authenticator will not be called', ['authenticator' => get_class($guardAuthenticator)]);

                break;
            }
        }
    }

    private function executeGuardAuthenticator(string $uniqueGuardKey, $guardAuthenticator, RequestEvent $event)
    {
        $request = $event->getRequest();
        $previousToken = $this->tokenStorage?->getToken();
        try {
            $this->logger?->debug('Calling getCredentials() on guard authenticator.', ['firewall_key' => $this->providerKey, 'authenticator' => get_class($guardAuthenticator)]);

            $credentials = $guardAuthenticator->getCredentials($request);

            if (null === $credentials) {
                throw new UnexpectedValueException(sprintf('The return value of "%1$s::getCredentials()" must not be null. Return false from "%1$s::supports()" instead.', get_debug_type($guardAuthenticator)));
            }

            $token = new PreAuthenticationGuardToken($credentials, $uniqueGuardKey);

            $this->logger?->debug('Passing guard token information to the GuardAuthenticationProvider', ['firewall_key' => $this->providerKey, 'authenticator' => get_class($guardAuthenticator)]);

            $token = $this->authenticationManager->authenticate($token);

            $this->logger?->info('Guard authentication successful!', ['token' => $token, 'authenticator' => get_class($guardAuthenticator)]);

            if ($this->tokenStorage) {
                $this->guardHandler->authenticateWithToken($token, $request, $this->providerKey, $previousToken);
            } else {
                $this->guardHandler->authenticateWithToken($token, $request, $this->providerKey);
            }
        } catch (AuthenticationException $e) {
            $this->logger?->info('Guard authentication failed.', ['exception' => $e, 'authenticator' => get_class($guardAuthenticator)]);

            if ($this->hideUserNotFoundExceptions && ($e instanceof UserNotFoundException || ($e instanceof AccountStatusException && !$e instanceof CustomUserMessageAccountStatusException))) {
                $e = new BadCredentialsException('Bad credentials.', 0, $e);
            }

            $response = $this->guardHandler->handleAuthenticationFailure($e, $request, $guardAuthenticator, $this->providerKey);

            if ($response instanceof Response) {
                $event->setResponse($response);
            }

            return;
        }

        $response = $this->guardHandler->handleAuthenticationSuccess($token, $request, $guardAuthenticator, $this->providerKey);
        if ($response instanceof Response) {
            $this->logger?->debug('Guard authenticator set success response.', ['response' => $response, 'authenticator' => get_class($guardAuthenticator)]);

            $event->setResponse($response);
        } else {
            $this->logger?->debug('Guard authenticator set no success response: request continues.', ['authenticator' => get_class($guardAuthenticator)]);
        }

        $this->triggerRememberMe($guardAuthenticator, $request, $token, $response);
    }

    public function setRememberMeServices($rememberMeServices)
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    private function triggerRememberMe($guardAuthenticator, Request $request, TokenInterface $token, ?Response $response = null)
    {
        if (null === $this->rememberMeServices) {
            $this->logger?->debug('Remember me skipped: it is not configured for the firewall.', ['authenticator' => get_class($guardAuthenticator)]);
            return;
        }

        if (!$guardAuthenticator->supportsRememberMe()) {
            $this->logger?->debug('Remember me skipped: your authenticator does not support it.', ['authenticator' => get_class($guardAuthenticator)]);
            return;
        }

        if (!$response instanceof Response) {
            throw new LogicException(sprintf('"%s::onAuthenticationSuccess()" *must* return a Response if you want to use the remember me functionality. Return a Response, or set remember_me to false under the guard configuration.', get_debug_type($guardAuthenticator)));
        }

        $this->rememberMeServices->loginSuccess($request, $response, $token);
    }
}