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

use Swift_Message;

/**
 * Swiftmailer trait.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
trait SwiftmailerTrait
{
    /**
     * Sends an email.
     *
     * @param Swift_Message $message          A \Swift_Message instance
     * @param array|null $failedRecipients An array of failures by-reference
     *
     * @return int|null The number of sent messages
     */
    public function mail(Swift_Message $message, array &$failedRecipients = null): ?int
    {
        return $this['mailer']->send($message, $failedRecipients);
    }
}