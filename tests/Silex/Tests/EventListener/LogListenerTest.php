<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\EventListener;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use RuntimeException;
use Silex\EventListener\LogListener;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * LogListener.
 *
 * @author Jérôme Tamarelle <jerome@tamarelle.net>
 */
class LogListenerTest extends TestCase
{
    public function testRequestListener()
    {
        /** @var LoggerInterface&MockObject $logger */
        $logger = $this->getMockBuilder('Psr\\Log\\LoggerInterface')->getMock();
        $logger
            ->expects($this->once())
            ->method('log')
            ->with(LogLevel::DEBUG, '> GET /foo');

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LogListener($logger));

        /** @var HttpKernelInterface&MockObject $kernel */
        $kernel = $this->getMockBuilder('Symfony\\Component\\HttpKernel\\HttpKernelInterface')->getMock();

        $dispatcher->dispatch(new RequestEvent($kernel, Request::create('/subrequest'), HttpKernelInterface::SUB_REQUEST), KernelEvents::REQUEST, 'Skip sub requests');

        $dispatcher->dispatch(new RequestEvent($kernel, Request::create('/foo'), HttpKernelInterface::MASTER_REQUEST), KernelEvents::REQUEST, 'Log master requests');
    }

    public function testResponseListener()
    {
        /** @var LoggerInterface&MockObject $logger */
        $logger = $this->getMockBuilder('Psr\\Log\\LoggerInterface')->getMock();
        $logger
            ->expects($this->once())
            ->method('log')
            ->with(LogLevel::DEBUG, '< 301');

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LogListener($logger));

        /** @var HttpKernelInterface&MockObject $kernel */
        $kernel = $this->getMockBuilder('Symfony\\Component\\HttpKernel\\HttpKernelInterface')->getMock();

        $dispatcher->dispatch(new ResponseEvent($kernel, Request::create('/foo'), HttpKernelInterface::SUB_REQUEST, Response::create('subrequest')), KernelEvents::RESPONSE, 'Skip sub requests');

        $dispatcher->dispatch(new ResponseEvent($kernel, Request::create('/foo'), HttpKernelInterface::MASTER_REQUEST, Response::create('bar', 301)), KernelEvents::RESPONSE, 'Log master requests');
    }

    public function testExceptionListener()
    {
        /** @var LoggerInterface&MockObject $logger */
        $logger = $this->getMockBuilder('Psr\\Log\\LoggerInterface')->getMock();
        $logger
            ->expects($this->exactly(2))
            ->method('log')
            ->with(
                $this->logicalOr(
                    $this->equalTo([LogLevel::CRITICAL, 'RuntimeException: Fatal error (uncaught exception) at '.__FILE__.' line '.(__LINE__ + 11)]),
                    $this->equalTo([LogLevel::ERROR, 'Symfony\Component\HttpKernel\Exception\HttpException: Http error (uncaught exception) at '.__FILE__.' line '.(__LINE__ + 11)])
                )
            );

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LogListener($logger));

        /** @var HttpKernelInterface&MockObject $kernel */
        $kernel = $this->getMockBuilder('Symfony\\Component\\HttpKernel\\HttpKernelInterface')->getMock();

        $dispatcher->dispatch(new ExceptionEvent($kernel, Request::create('/foo'), HttpKernelInterface::SUB_REQUEST, new RuntimeException('Fatal error')), KernelEvents::EXCEPTION);
        $dispatcher->dispatch(new ExceptionEvent($kernel, Request::create('/foo'), HttpKernelInterface::SUB_REQUEST, new HttpException(400, 'Http error')), KernelEvents::EXCEPTION);
    }
}