<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex;

use ReflectionClass;
use ReflectionException;
use ReflectionFunction;
use ReflectionMethod;
use ReflectionObject;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ViewEvent;

/**
 * Wraps view listeners.
 *
 * @author Dave Marshall <dave@atst.io>
 */
class ViewListenerWrapper
{
    private $app;
    private $callback;

    /**
     * Constructor.
     *
     * @param Application $app      An Application instance
     * @param mixed       $callback
     */
    public function __construct(Application $app, $callback)
    {
        $this->app = $app;
        $this->callback = $callback;
    }

    /**
     * @throws ReflectionException
     */
    public function __invoke(ViewEvent $event)
    {
        $controllerResult = $event->getControllerResult();
        $callback = $this->app['callback_resolver']->resolveCallback($this->callback);

        if (!$this->shouldRun($callback, $controllerResult)) {
            return;
        }

        $response = call_user_func($callback, $controllerResult, $event->getRequest());

        if ($response instanceof Response) {
            $event->setResponse($response);
        } elseif (null !== $response) {
            $event->setControllerResult($response);
        }
    }

    /**
     * @throws ReflectionException
     */
    private function shouldRun($callback, $controllerResult): bool
    {
        if (is_array($callback)) {
            $callbackReflection = new ReflectionMethod($callback[0], $callback[1]);
        } elseif (is_object($callback) && !$callback instanceof \Closure) {
            $callbackReflection = new ReflectionObject($callback);
            $callbackReflection = $callbackReflection->getMethod('__invoke');
        } else {
            $callbackReflection = new ReflectionFunction($callback);
        }

        if ($callbackReflection->getNumberOfParameters() > 0) {
            $parameters = $callbackReflection->getParameters();
            $expectedControllerResult = $parameters[0];
            $reflectedClass = $expectedControllerResult->getType() && !$expectedControllerResult->getType()->isBuiltin()
                ? new ReflectionClass($expectedControllerResult->getType()->getName())
                : null;

            if (null !== $reflectedClass && (!is_object($controllerResult) || !$reflectedClass->isInstance($controllerResult))) {
                return false;
            }

            if ($expectedControllerResult->getType() && 'array' === $expectedControllerResult->getType()->getName() && !is_array($controllerResult)) {
                return false;
            }

            if ($expectedControllerResult->getType() && 'callable' === $expectedControllerResult->getType()->getName() && !is_callable($controllerResult)) {
                return false;
            }
        }

        return true;
    }
}