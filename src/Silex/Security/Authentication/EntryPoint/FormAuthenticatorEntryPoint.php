<?php

declare(strict_types=1);

namespace Silex\Security\Authentication\EntryPoint;

use Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

class FormAuthenticatorEntryPoint implements AuthenticationEntryPointInterface
{
    private $loginPath;
    private $useForward;
    private $httpKernel;
    private $httpUtils;

    public function __construct(HttpKernelInterface $kernel, HttpUtils $httpUtils, string $loginPath, bool $useForward = false)
    {
        $this->httpKernel = $kernel;
        $this->httpUtils = $httpUtils;
        $this->loginPath = $loginPath;
        $this->useForward = $useForward;
    }

    /**
     * @throws Exception
     */
    public function start(Request $request, ?AuthenticationException $authException = null)
    {
        if ($this->useForward) {
            $subRequest = $this->httpUtils->createRequest($request, $this->loginPath);

            $response = $this->httpKernel->handle($subRequest, HttpKernelInterface::SUB_REQUEST);
            if (200 === $response->getStatusCode()) {
                $response->setStatusCode(401);
            }

            return $response;
        }

        return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
    }
}