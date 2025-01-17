<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider\Session;

use Pimple\Container;
use Pimple\Psr11\Container as Psr11Container;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\EventListener\SessionListener as BaseSessionListener;

/**
 * Sets the session in the request.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class SessionListener extends BaseSessionListener
{
    private $app;

    public function __construct(Container $app)
    {
        $this->app = $app;
        parent::__construct(new Psr11Container($app));
    }

    protected function getSession(): ?SessionInterface
    {
        if (!isset($this->app['session'])) {
            return null;
        }

        return $this->app['session'];
    }
}