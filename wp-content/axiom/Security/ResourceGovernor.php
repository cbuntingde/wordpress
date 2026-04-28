<?php
/**
 * Resource Governor — Hard Quotas for CPU and Memory
 *
 * Monitors plugin execution time and memory consumption during
 * hook callbacks. If a plugin exceeds its configured budget,
 * the governor gracefully terminates the isolate without crashing
 * the WordPress process.
 *
 * Uses declare(ticks=1) to intercept execution at every tick and
 * check resource consumption against the configured limits.
 *
 * @package Axiom\Security
 */

declare(strict_types=1);

namespace Axiom\Security;

use Axiom\Kernel\KernelConfig;
use Axiom\Kernel\PluginContext;
use Axiom\Profiler\AuditLogger;

final class ResourceGovernor
{
    private KernelConfig $config;
    private AuditLogger $logger;

    private ?PluginContext $current_context = null;
    private int $tick_start = 0;
    private bool $ticks_registered = false;

    public function __construct( KernelConfig $config, ?AuditLogger $logger = null )
    {
        $this->config = $config;
        $this->logger = $logger ?? new AuditLogger( $config );
    }

    /**
     * Register the tick handler for execution monitoring.
     */
    public function register(): void
    {
        if ( $this->ticks_registered ) {
            return;
        }

        if ( function_exists( 'register_tick_function' ) ) {
            register_tick_function( [ $this, 'tick' ] );
        }

        $this->ticks_registered = true;
    }

    /**
     * Begin monitoring a plugin context for the duration of a hook.
     */
    public function begin( PluginContext $context ): void
    {
        $this->current_context = $context;
        $this->tick_start      = (int) ( microtime( true ) * 1000 );
        $context->reset_budget();
    }

    /**
     * End monitoring. Record final resource usage.
     */
    public function end(): void
    {
        if ( $this->current_context === null ) {
            return;
        }

        $elapsed = (int) ( microtime( true ) * 1000 ) - $this->tick_start;
        $memory  = memory_get_peak_usage( true );

        $this->current_context->record_cpu( $elapsed );
        $this->current_context->record_memory( $memory );

        $this->current_context = null;
    }

    /**
     * Tick handler — called on every PHP tick.
     * Checks if the current plugin has exceeded its resource budget.
     */
    public function tick(): void
    {
        if ( $this->current_context === null ) {
            return;
        }

        $elapsed = (int) ( microtime( true ) * 1000 ) - $this->tick_start;
        $memory  = memory_get_usage( true );
        $memory_mb = $memory / ( 1024 * 1024 );

        $cpu_limit  = $this->current_context->manifest()?->cpu_limit_ms()
            ?: $this->config->cpu_limit_ms();
        $mem_limit  = $this->current_context->manifest()?->memory_limit_mb()
            ?: $this->config->memory_limit_mb();

        if ( $elapsed > $cpu_limit || $memory_mb > $mem_limit ) {
            $this->terminate( $elapsed, $memory_mb, $cpu_limit, $mem_limit );
        }
    }

    /**
     * Gracefully terminate the current plugin isolate.
     */
    private function terminate( int $elapsed_ms, float $memory_mb, int $cpu_limit, int $mem_limit ): void
    {
        $context = $this->current_context;
        if ( $context === null ) {
            return;
        }

        $this->logger->log( AuditLogger::ERROR, 'Resource exhaustion — isolate terminated', [
            'plugin'    => $context->slug(),
            'elapsed_ms' => $elapsed_ms,
            'memory_mb'  => round( $memory_mb, 2 ),
            'cpu_limit'  => $cpu_limit,
            'mem_limit'  => $mem_limit,
        ] );

        $context->deactivate();
        $this->current_context = null;

        throw new ResourceExhaustedException(
            sprintf(
                'Plugin "%s" exceeded resource budget (%d ms CPU, %d MB memory)',
                $context->slug(),
                $cpu_limit,
                $mem_limit
            )
        );
    }

    /**
     * Get the currently monitored context, if any.
     */
    public function current_context(): ?PluginContext
    {
        return $this->current_context;
    }
}
