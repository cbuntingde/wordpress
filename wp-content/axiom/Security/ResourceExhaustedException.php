<?php
/**
 * Resource Exhausted Exception
 *
 * Thrown when a plugin exceeds its CPU or memory budget.
 * Caught by the HookMarshaller so that a single runaway plugin
 * never crashes the entire WordPress process.
 *
 * @package Axiom\Security
 */

declare(strict_types=1);

namespace Axiom\Security;

class ResourceExhaustedException extends \RuntimeException
{
}
