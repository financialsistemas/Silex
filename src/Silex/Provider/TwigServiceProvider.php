<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use ReflectionClass;
use Silex\Provider\Twig\RuntimeLoader;
use Symfony\Bridge\Twig\AppVariable;
use Symfony\Bridge\Twig\Extension\AssetExtension;
use Symfony\Bridge\Twig\Extension\DumpExtension;
use Symfony\Bridge\Twig\Extension\FormExtension;
use Symfony\Bridge\Twig\Extension\HttpFoundationExtension;
use Symfony\Bridge\Twig\Extension\HttpKernelExtension;
use Symfony\Bridge\Twig\Extension\HttpKernelRuntime;
use Symfony\Bridge\Twig\Extension\RoutingExtension;
use Symfony\Bridge\Twig\Extension\SecurityExtension;
use Symfony\Bridge\Twig\Extension\TranslationExtension;
use Symfony\Bridge\Twig\Extension\WebLinkExtension;
use Symfony\Bridge\Twig\Form\TwigRendererEngine;
use Symfony\Component\Form\FormRenderer;
use Symfony\Component\HttpFoundation\UrlHelper;
use Symfony\Component\HttpKernel\Fragment\HIncludeFragmentRenderer;
use Twig\Environment as TwigEnvironment;
use Twig\Extension\CoreExtension;
use Twig\Extension\DebugExtension;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;


/**
 * Twig integration for Silex.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class TwigServiceProvider implements ServiceProviderInterface
{
    public function register(Container $app)
    {
        $app['twig.options'] = [];
        $app['twig.form.templates'] = ['form_div_layout.html.twig'];
        $app['twig.path'] = [];
        $app['twig.templates'] = [];

        $app['twig.date.format'] = 'F j, Y H:i';
        $app['twig.date.interval_format'] = '%d days';
        $app['twig.date.timezone'] = null;

        $app['twig.number_format.decimals'] = 0;
        $app['twig.number_format.decimal_point'] = '.';
        $app['twig.number_format.thousands_separator'] = ',';

        $app['twig'] = function ($app) {
            /** @var TwigEnvironment $twig */
            $twig = $app['twig.environment_factory']($app);
            // registered for BC, but should not be used anymore
            // deprecated and should probably be removed in Silex 3.0
            $twig->addGlobal('app', $app);

            $coreExtension = $twig->getExtension(CoreExtension::class);

            $coreExtension->setDateFormat($app['twig.date.format'], $app['twig.date.interval_format']);

            if (null !== $app['twig.date.timezone']) {
                $coreExtension->setTimezone($app['twig.date.timezone']);
            }

            $coreExtension->setNumberFormat($app['twig.number_format.decimals'], $app['twig.number_format.decimal_point'], $app['twig.number_format.thousands_separator']);

            if ($app['debug']) {
                $twig->addExtension(new DebugExtension());
            }

            if (class_exists('Symfony\Bridge\Twig\Extension\RoutingExtension')) {
                if (!isset($app['twig.app_variable'])) {
                    $app['twig.app_variable'] = function ($app) {
                        $var = new AppVariable();
                        if (isset($app['security.token_storage'])) {
                            $var->setTokenStorage($app['security.token_storage']);
                        }
                        if (isset($app['request_stack'])) {
                            $var->setRequestStack($app['request_stack']);
                        }
                        $var->setDebug($app['debug']);

                        return $var;
                    };
                }

                $twig->addGlobal('global', $app['twig.app_variable']);

                if (isset($app['request_stack'])) {
                    $twig->addExtension(new HttpFoundationExtension(new UrlHelper($app['request_stack'], $app['request_context'])));
                    $twig->addExtension(new RoutingExtension($app['url_generator']));
                }

                if (isset($app['translator'])) {
                    $twig->addExtension(new TranslationExtension($app['translator']));
                }

                if (isset($app['security.authorization_checker'])) {
                    $twig->addExtension(new SecurityExtension($app['security.authorization_checker']));
                }

                if (isset($app['fragment.handler'])) {
                    $app['fragment.renderer.hinclude'] = function ($app) {
                        $renderer = new HIncludeFragmentRenderer($app['twig'], $app['uri_signer'], $app['fragment.renderer.hinclude.global_template'], $app['charset']);
                        $renderer->setFragmentPath($app['fragment.path']);
                        return $renderer;
                    };

                    $twig->addExtension(new HttpKernelExtension());
                }

                if (isset($app['assets.packages'])) {
                    $twig->addExtension(new AssetExtension($app['assets.packages']));
                }

                if (isset($app['form.factory'])) {
                    $app['twig.form.engine'] = function ($app) use ($twig) {
                        return new TwigRendererEngine($app['twig.form.templates'], $twig);
                    };

                    $app['twig.form.renderer'] = function ($app) {
                        $csrfTokenManager = $app['csrf.token_manager'] ?? null;

                        return new FormRenderer($app['twig.form.engine'], $csrfTokenManager);
                    };

                    $twig->addExtension(new FormExtension());

                    // add loader for Symfony built-in form templates
                    $reflected = new ReflectionClass('Symfony\Bridge\Twig\Extension\FormExtension');
                    $path = dirname($reflected->getFileName()).'/../Resources/views/Form';
                    $app['twig.loader']->addLoader(new FilesystemLoader($path));
                }

                if (isset($app['var_dumper.cloner'])) {
                    $twig->addExtension(new DumpExtension($app['var_dumper.cloner']));
                }

                $twig->addRuntimeLoader($app['twig.runtime_loader']);
                $twig->addExtension(new WebLinkExtension($app['request_stack']));
            }

            return $twig;
        };

        $app['twig.loader.filesystem'] = function ($app) {
            $loader = new FilesystemLoader();
            foreach (is_array($app['twig.path']) ? $app['twig.path'] : [$app['twig.path']] as $key => $val) {
                if (is_string($key)) {
                    $loader->addPath($key, $val);
                } else {
                    $loader->addPath($val);
                }
            }

            return $loader;
        };

        $app['twig.loader.array'] = function ($app) {
            return new ArrayLoader($app['twig.templates']);
        };

        $app['twig.loader'] = function ($app) {
            return new ChainLoader([
                $app['twig.loader.array'],
                $app['twig.loader.filesystem'],
            ]);
        };

        $app['twig.environment_factory'] = $app->protect(function ($app) {
            return new TwigEnvironment($app['twig.loader'], array_replace([
                'charset' => $app['charset'],
                'debug' => $app['debug'],
                'strict_variables' => $app['debug'],
            ], $app['twig.options']));
        });

        $app['twig.runtime.httpkernel'] = function ($app) {
            return new HttpKernelRuntime($app['fragment.handler']);
        };

        $app['twig.runtimes'] = function ($app) {
            return [
                HttpKernelRuntime::class => 'twig.runtime.httpkernel',
                FormRenderer::class => 'twig.form.renderer',
            ];
        };

        $app['twig.runtime_loader'] = function ($app) {
            return new RuntimeLoader($app, $app['twig.runtimes']);
        };
    }
}