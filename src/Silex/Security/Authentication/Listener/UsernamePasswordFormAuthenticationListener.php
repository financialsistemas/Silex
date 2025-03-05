<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\Listener;

use LogicException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\PropertyAccess\Exception\AccessException;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use function is_object;
use function is_string;
use function strlen;

class UsernamePasswordFormAuthenticationListener extends AbstractAuthenticationListener
{
    private $csrfTokenManager;

    private static $propertyAccessor;

    public function __construct(TokenStorageInterface $tokenStorage, /*AuthenticationManagerInterface*/ $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = [], ?LoggerInterface $logger = null, ?EventDispatcherInterface $dispatcher = null, ?CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge([
            'username_parameter' => '_username',
            'password_parameter' => '_password',
            'csrf_parameter' => '_csrf_token',
            'csrf_token_id' => 'authenticate',
            'post_only' => true,
        ], $options), $logger, $dispatcher);

        $this->csrfTokenManager = $csrfTokenManager;
    }

    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('POST')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }

    protected function attemptAuthentication(Request $request)
    {
        if (null !== $this->csrfTokenManager) {
            $csrfToken = $this->getRequestParameterValue($request, $this->options['csrf_parameter']);

            if (!is_string($csrfToken) || false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        if ($this->options['post_only']) {
            $username = $this->getParameterBagValue($request->request, $this->options['username_parameter']);
            $password = $this->getParameterBagValue($request->request, $this->options['password_parameter']);
        } else {
            $username = $this->getRequestParameterValue($request, $this->options['username_parameter']);
            $password = $this->getRequestParameterValue($request, $this->options['password_parameter']);
        }

        if (!is_string($username) && (!is_object($username) || !method_exists($username, '__toString'))) {
            throw new BadRequestHttpException(sprintf('The key "%s" must be a string, "%s" given.', $this->options['username_parameter'], get_debug_type($username)));
        }

        $username = trim($username);

        if (strlen($username) > Security::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        if (null === $password) {
            throw new LogicException(sprintf('The key "%s" cannot be null; check that the password field name of the form matches.', $this->options['password_parameter']));
        }

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->providerKey));
    }

    public static function getRequestParameterValue(Request $request, string $path)
    {
        if (false === $pos = strpos($path, '[')) {
            return $request->get($path);
        }

        $root = substr($path, 0, $pos);

        if (null === $value = $request->get($root)) {
            return null;
        }

        if (null === self::$propertyAccessor) {
            self::$propertyAccessor = PropertyAccess::createPropertyAccessor();
        }

        try {
            return self::$propertyAccessor->getValue($value, substr($path, $pos));
        } catch (AccessException $e) {
            return null;
        }
    }

    public static function getParameterBagValue(ParameterBag $parameters, string $path)
    {
        if (false === $pos = strpos($path, '[')) {
            return $parameters->all()[$path] ?? null;
        }

        $root = substr($path, 0, $pos);

        if (null === $value = $parameters->all()[$root] ?? null) {
            return null;
        }

        if (null === self::$propertyAccessor) {
            self::$propertyAccessor = PropertyAccess::createPropertyAccessor();
        }

        try {
            return self::$propertyAccessor->getValue($value, substr($path, $pos));
        } catch (AccessException $e) {
            return null;
        }
    }
}