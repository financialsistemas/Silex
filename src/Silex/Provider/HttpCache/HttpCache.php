<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider\HttpCache;

use Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpCache\HttpCache as BaseHttpCache;

/**
 * HTTP Cache extension to allow using the run() shortcut.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class HttpCache extends BaseHttpCache
{
    /**
     * Handles the Request and delivers the Response.
     *
     * @param Request|null $request The Request object
     * @throws Exception
     */
    public function run(Request $request = null)
    {
        if (null === $request) {
            $request = Request::createFromGlobals();
        }

        $response = $this->handle($request);
        $response->send();
        $this->terminate($request, $response);
    }
}