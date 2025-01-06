<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Application;

/**
 * Translation trait.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
trait TranslationTrait
{
    /**
     * Translates the given message.
     *
     * @param string $id         The message id
     * @param array  $parameters An array of parameters for the message
     * @param string $domain     The domain for the message
     * @param string|null $locale     The locale
     *
     * @return string|null The translated string
     */
    public function trans(string $id, array $parameters = [], string $domain = 'messages', string $locale = null): ?string
    {
        return $this['translator']->trans($id, $parameters, $domain, $locale);
    }
}