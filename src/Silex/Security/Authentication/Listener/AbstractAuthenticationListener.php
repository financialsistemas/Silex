<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Listener;

use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\SessionUnavailableException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

abstract class AbstractAuthenticationListener extends AbstractListener
{
    protected $options;
    protected $logger;
    protected $authenticationManager;
    protected $providerKey;
    protected $httpUtils;

    private $tokenStorage;
    private $sessionStrategy;
    private $dispatcher;
    private $successHandler;
    private $failureHandler;
    private $rememberMeServices;

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(TokenStorageInterface $tokenStorage, /*AuthenticationManagerInterface*/ $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = [], ?LoggerInterface $logger = null, ?EventDispatcherInterface $dispatcher = null)
    {
        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->sessionStrategy = $sessionStrategy;
        $this->providerKey = $providerKey;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->options = array_merge([
            'check_path' => '/login_check',
            'login_path' => '/login',
            'always_use_default_target_path' => false,
            'default_target_path' => '/',
            'target_path_parameter' => '_target_path',
            'use_referer' => false,
            'failure_path' => null,
            'failure_forward' => false,
            'require_previous_session' => true,
        ], $options);
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
        $this->httpUtils = $httpUtils;
    }

    /**
     * Sets the RememberMeServices implementation to use.
     */
    public function setRememberMeServices($rememberMeServices)
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    public function supports(Request $request): ?bool
    {
        return $this->requiresAuthentication($request);
    }

    /**
     * Handles form based authentication.
     *
     * @throws RuntimeException
     * @throws SessionUnavailableException
     */
    public function authenticate(RequestEvent $event)
    {
        $request = $event->getRequest();

        if (!$request->hasSession()) {
            throw new RuntimeException('This authentication method requires a session.');
        }

        try {
            if ($this->options['require_previous_session'] && !$request->hasPreviousSession()) {
                throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
            }

            $previousToken = $this->tokenStorage->getToken();

            if (null === $returnValue = $this->attemptAuthentication($request)) {
                return;
            }

            if ($returnValue instanceof TokenInterface) {
                $this->migrateSession($request, $returnValue, $previousToken);

                $response = $this->onSuccess($request, $returnValue);
            } elseif ($returnValue instanceof Response) {
                $response = $returnValue;
            } else {
                throw new RuntimeException('attemptAuthentication() must either return a Response, an implementation of TokenInterface, or null.');
            }
        } catch (AuthenticationException $e) {
            $response = $this->onFailure($request, $e);
        }

        $event->setResponse($response);
    }

    /**
     *
     * @return bool
     */
    protected function requiresAuthentication(Request $request)
    {
        return $this->httpUtils->checkRequestPath($request, $this->options['check_path']);
    }

    /**
     * Performs authentication.
     *
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a Response
     *
     * @throws AuthenticationException if the authentication fails
     */
    abstract protected function attemptAuthentication(Request $request);

    private function onFailure(Request $request, AuthenticationException $failed): Response
    {
        $this->logger?->info('Authentication request failed.', ['exception' => $failed]);

        $token = $this->tokenStorage->getToken();
        if ($token instanceof UsernamePasswordToken && $this->providerKey === $token->getFirewallName()) {
            $this->tokenStorage->setToken();
        }

        $response = $this->failureHandler->onAuthenticationFailure($request, $failed);

        if (!$response instanceof Response) {
            throw new RuntimeException('Authentication Failure Handler did not return a Response.');
        }

        return $response;
    }

    private function onSuccess(Request $request, TokenInterface $token): Response
    {
        $this->logger?->info('User has been authenticated successfully.', ['username' => method_exists($token, 'getUserIdentifier') ? $token->getUserIdentifier() : $token->getUsername()]);

        $this->tokenStorage->setToken($token);

        $session = $request->getSession();
        $session->remove(Security::AUTHENTICATION_ERROR);
        $session->remove(Security::LAST_USERNAME);

        if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch($loginEvent, SecurityEvents::INTERACTIVE_LOGIN);
        }

        $response = $this->successHandler->onAuthenticationSuccess($request, $token);

        if (!$response instanceof Response) {
            throw new RuntimeException('Authentication Success Handler did not return a Response.');
        }

        $this->rememberMeServices?->loginSuccess($request, $response, $token);

        return $response;
    }

    private function migrateSession(Request $request, TokenInterface $token, ?TokenInterface $previousToken)
    {
        if ($previousToken) {
            $user = method_exists($token, 'getUserIdentifier') ? $token->getUserIdentifier() : $token->getUsername();
            $previousUser = method_exists($previousToken, 'getUserIdentifier') ? $previousToken->getUserIdentifier() : $previousToken->getUsername();

            if ('' !== ($user ?? '') && $user === $previousUser) {
                return;
            }
        }

        $this->sessionStrategy->onAuthentication($request, $token);
    }
}