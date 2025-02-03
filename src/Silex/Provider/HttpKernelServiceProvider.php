<?php

namespace Silex\Provider;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Api\EventListenerProviderInterface;
use Silex\AppArgumentValueResolver;
use Silex\CallbackResolver;
use Silex\EventListener\ConverterListener;
use Silex\EventListener\MiddlewareListener;
use Silex\EventListener\StringToResponseListener;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Controller\ArgumentResolver;
use Symfony\Component\HttpKernel\Controller\ControllerResolver;
use Symfony\Component\HttpKernel\ControllerMetadata\ArgumentMetadataFactory;
use Symfony\Component\HttpKernel\EventListener\ResponseListener;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\WebLink\EventListener\AddLinkHeaderListener;
use Symfony\Component\WebLink\HttpHeaderSerializer;

class HttpKernelServiceProvider implements ServiceProviderInterface, EventListenerProviderInterface
{
    /**
     * {@inheritdoc}
     */
    public function register(Container $app)
    {
        $app['resolver'] = (fn($app) => new ControllerResolver($app['logger']));

        $app['argument_metadata_factory'] = (fn($app) => new ArgumentMetadataFactory());
        $app['argument_value_resolvers'] = (fn($app) => array_merge([new AppArgumentValueResolver($app)], ArgumentResolver::getDefaultArgumentValueResolvers()));

        $app['argument_resolver'] = (fn($app) => new ArgumentResolver($app['argument_metadata_factory'], $app['argument_value_resolvers']));

        $app['kernel'] = (fn($app) => new HttpKernel($app['dispatcher'], $app['resolver'], $app['request_stack'], $app['argument_resolver']));

        $app['request_stack'] = (fn() => new RequestStack());

        $app['dispatcher'] = (fn() => new EventDispatcher());

        $app['callback_resolver'] = (fn($app) => new CallbackResolver($app));
    }

    public function subscribe(Container $app, EventDispatcherInterface $dispatcher)
    {
        $dispatcher->addSubscriber(new ResponseListener($app['charset']));
        $dispatcher->addSubscriber(new MiddlewareListener($app));
        $dispatcher->addSubscriber(new ConverterListener($app['routes'], $app['callback_resolver']));
        $dispatcher->addSubscriber(new StringToResponseListener());

        if (class_exists(HttpHeaderSerializer::class)) {
            $dispatcher->addSubscriber(new AddLinkHeaderListener());
        }
    }
}