<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests;

use Exception;
use PHPUnit\Framework\TestCase;
use Silex\Application;
use Silex\Route;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Router test cases.
 *
 * @author Igor Wiedler <igor@wiedler.ch>
 */
class RouterTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testMapRouting()
    {
        $app = new Application();

        $app->match('/foo', function () {
            return 'foo';
        });

        $app->match('/bar', function () {
            return 'bar';
        });

        $app->match('/', function () {
            return 'root';
        });

        $this->checkRouteResponse($app, '/foo', 'foo');
        $this->checkRouteResponse($app, '/bar', 'bar');
        $this->checkRouteResponse($app, '/', 'root');
    }

    /**
     * @throws Exception
     */
    public function testStatusCode()
    {
        $app = new Application();

        $app->put('/created', function () {
            return new Response('', 201);
        });

        $app->match('/forbidden', function () {
            return new Response('', 403);
        });

        $app->match('/not_found', function () {
            return new Response('', 404);
        });

        $request = Request::create('/created', 'put');
        $response = $app->handle($request);
        $this->assertEquals(201, $response->getStatusCode());

        $request = Request::create('/forbidden');
        $response = $app->handle($request);
        $this->assertEquals(403, $response->getStatusCode());

        $request = Request::create('/not_found');
        $response = $app->handle($request);
        $this->assertEquals(404, $response->getStatusCode());
    }

    /**
     * @throws Exception
     */
    public function testRedirect()
    {
        $app = new Application();

        $app->match('/redirect', function () {
            return new RedirectResponse('/target');
        });

        $app->match('/redirect2', function () use ($app) {
            return $app->redirect('/target2');
        });

        $request = Request::create('/redirect');
        $response = $app->handle($request);
        $this->assertTrue($response->isRedirect('/target'));

        $request = Request::create('/redirect2');
        $response = $app->handle($request);
        $this->assertTrue($response->isRedirect('/target2'));
    }

    /**
     * @throws Exception
     */
    public function testMissingRoute()
    {
        $this->expectException(NotFoundHttpException::class);

        $app = new Application();
        unset($app['exception_handler']);

        $request = Request::create('/baz');
        $app->handle($request);
    }

    /**
     * @throws Exception
     */
    public function testMethodRouting()
    {
        $app = new Application();

        $app->match('/foo', function () {
            return 'foo';
        });

        $app->match('/bar', function () {
            return 'bar';
        })->method('GET|POST');

        $app->get('/resource', function () {
            return 'get resource';
        });

        $app->post('/resource', function () {
            return 'post resource';
        });

        $app->put('/resource', function () {
            return 'put resource';
        });

        $app->patch('/resource', function () {
            return 'patch resource';
        });

        $app->delete('/resource', function () {
            return 'delete resource';
        });

        $this->checkRouteResponse($app, '/foo', 'foo');
        $this->checkRouteResponse($app, '/bar', 'bar');
        $this->checkRouteResponse($app, '/bar', 'bar', 'post');
        $this->checkRouteResponse($app, '/resource', 'get resource');
        $this->checkRouteResponse($app, '/resource', 'post resource', 'post');
        $this->checkRouteResponse($app, '/resource', 'put resource', 'put');
        $this->checkRouteResponse($app, '/resource', 'patch resource', 'patch');
        $this->checkRouteResponse($app, '/resource', 'delete resource', 'delete');
    }

    /**
     * @throws Exception
     */
    public function testRequestShouldBeStoredRegardlessOfRouting()
    {
        $app = new Application();

        $app->get('/foo', function (Request $request) {
            return new Response($request->getRequestUri());
        });

        $app->error(function ($e, Request $request, $code) {
            return new Response($request->getRequestUri());
        });

        foreach (['/foo', '/bar'] as $path) {
            $request = Request::create($path);
            $response = $app->handle($request);
            $this->assertStringContainsString($path, $response->getContent());
        }
    }

    /**
     * @throws Exception
     */
    public function testTrailingSlashBehavior()
    {
        $app = new Application();

        $app->get('/foo/', function () {
            return new Response('ok');
        });

        $request = Request::create('/foo');
        $response = $app->handle($request);

        $this->assertEquals(301, $response->getStatusCode());
        $this->assertEquals('/foo/', $response->getTargetUrl());
    }

    public function testHostSpecification()
    {
        $route = new Route();

        $this->assertSame($route, $route->host('{locale}.example.com'));
        $this->assertEquals('{locale}.example.com', $route->getHost());
    }

    /**
     * @throws Exception
     */
    public function testRequireHttpRedirect()
    {
        $app = new Application();

        $app->match('/secured', function () {
            return 'secured content';
        })
        ->requireHttp();

        $request = Request::create('http://example.com/secured');
        $response = $app->handle($request);
        $this->assertTrue($response->isRedirect('http://example.com/secured'));
    }

    /**
     * @throws Exception
     */
    public function testRequireHttpsRedirect()
    {
        $app = new Application();

        $app->match('/secured', function () {
            return 'secured content';
        })
        ->requireHttps();

        $request = Request::create('https://example.com/secured');
        $response = $app->handle($request);
        $this->assertTrue($response->isRedirect('https://example.com/secured'));
    }

    /**
     * @throws Exception
     */
    public function testRequireHttpsRedirectIncludesQueryString()
    {
        $app = new Application();

        $app->match('/secured', function () {
            return 'secured content';
        })
        ->requireHttps();

        $request = Request::create('https://example.com/secured?query=string');
        $response = $app->handle($request);
        $this->assertTrue($response->isRedirect('https://example.com/secured?query=string'));
    }

    /**
     * @throws Exception
     */
    public function testConditionOnRoute()
    {
        $app = new Application();
        $app->match('/secured', function () {
            return 'secured content';
        })
        ->when('request.isSecure() == true');

        $request = Request::create('http://example.com/secured');
        $response = $app->handle($request);
        $this->assertEquals(404, $response->getStatusCode());
    }

    /**
     * @throws Exception
     */
    public function testClassNameControllerSyntax()
    {
        $app = new Application();

        $app->get('/foo', 'Silex\Tests\MyController::getFoo');

        $this->checkRouteResponse($app, '/foo', 'foo');
    }

    /**
     * @throws Exception
     */
    public function testClassNameControllerSyntaxWithStaticMethod()
    {
        $app = new Application();

        $app->get('/bar', 'Silex\Tests\MyController::getBar');

        $this->checkRouteResponse($app, '/bar', 'bar');
    }

    /**
     * @throws Exception
     */
    protected function checkRouteResponse(Application $app, $path, $expectedContent, $method = 'get', $message = '')
    {
        $request = Request::create($path, $method);
        $response = $app->handle($request);
        $this->assertEquals($expectedContent, $response->getContent(), $message);
    }
}

class MyController
{
    public function getFoo(): string
    {
        return 'foo';
    }

    public static function getBar(): string
    {
        return 'bar';
    }
}