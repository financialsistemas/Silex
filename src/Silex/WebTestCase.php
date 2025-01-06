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

use LogicException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\HttpKernelBrowser;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * WebTestCase is the base class for functional tests.
 *
 * @author Igor Wiedler <igor@wiedler.ch>
 */
abstract class WebTestCase extends TestCase
{
    /**
     * HttpKernelInterface instance.
     *
     * @var HttpKernelInterface
     */
    protected $app;

    /**
     * PHPUnit setUp for setting up the application.
     *
     * Note: Child classes that define a setUp method must call
     * parent::setUp().
     */
    protected function setUp(): void
    {
        $this->app = $this->createApplication();
    }

    /**
     * Creates the application.
     *
     * @return HttpKernelInterface
     */
    abstract public function createApplication(): HttpKernelInterface;

    /**
     * Creates a Client.
     *
     * @param array $server Server parameters
     *
     * @return HttpKernelBrowser A Client instance
     */
    public function createClient(array $server = []): HttpKernelBrowser
    {
        if (!class_exists('Symfony\Component\HttpKernel\HttpKernelBrowser')) {
            throw new LogicException('Component "symfony/http-kernel" is required by WebTestCase.'.PHP_EOL.'Run composer require symfony/http-kernel');
        }

        return new HttpKernelBrowser($this->app, $server);
    }
}