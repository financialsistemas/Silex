<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\Provider;

use Silex\Application;
use Silex\Provider\RememberMeServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Silex\WebTestCase;
use Symfony\Component\HttpKernel\HttpKernelBrowser;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Http\SecurityEvents;

/**
 * SecurityServiceProvider.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class RememberMeServiceProviderTest extends WebTestCase
{
    public function testRememberMeAuthentication()
    {
        $app = $this->createApplication();

        $interactiveLogin = new InteractiveLoginTriggered();
        $app->on(SecurityEvents::INTERACTIVE_LOGIN, [$interactiveLogin, 'onInteractiveLogin']);

        $client = new HttpKernelBrowser($app);

        $client->request('get', '/');
        $this->assertFalse($interactiveLogin->triggered, 'The interactive login has not been triggered yet');
        $client->request('post', '/login_check', ['_username' => 'fabien', '_password' => 'foo', '_remember_me' => 'true']);
        $client->followRedirect();
        $this->assertEquals('AUTHENTICATED_FULLY', $client->getResponse()->getContent());
        $this->assertTrue($interactiveLogin->triggered, 'The interactive login has been triggered');

        $this->assertNotNull($client->getCookiejar()->get('REMEMBERME'), 'The REMEMBERME cookie is set');

        $client->getCookiejar()->expire('MOCKSESSID');

        $client->request('get', '/');
        $this->assertEquals('AUTHENTICATED_REMEMBERED', $client->getResponse()->getContent());
        $this->assertTrue($interactiveLogin->triggered, 'The interactive login has been triggered');

        $client->request('get', '/logout');
        $client->followRedirect();

        $this->assertNotNull($client->getCookiejar()->get('REMEMBERME'), 'The REMEMBERME cookie has been removed');
    }

    public function createApplication($authenticationMethod = 'form'): HttpKernelInterface
    {
        $app = new Application();

        $app['debug'] = true;
        unset($app['exception_handler']);

        $app->register(new SessionServiceProvider(), [
            'session.test' => true,
        ]);
        $app->register(new SecurityServiceProvider());
        $app->register(new RememberMeServiceProvider());

        $app['security.firewalls'] = [
            'http-auth' => [
                'pattern' => '^.*$',
                'form' => true,
                'remember_me' => [],
                'logout' => true,
                'users' => [
                    'fabien' => ['ROLE_USER', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
                ],
            ],
        ];

        $app->get('/', function () use ($app) {
            if ($app['security.authorization_checker']->isGranted('IS_AUTHENTICATED_FULLY')) {
                return 'AUTHENTICATED_FULLY';
            } elseif ($app['security.authorization_checker']->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
                return 'AUTHENTICATED_REMEMBERED';
            } else {
                return 'AUTHENTICATED_ANONYMOUSLY';
            }
        });

        return $app;
    }
}

class InteractiveLoginTriggered
{
    public $triggered = false;

    public function onInteractiveLogin()
    {
        $this->triggered = true;
    }
}