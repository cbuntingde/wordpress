<?php
/**
 * Isolate Manager — Dual-Execution Path Runtime
 *
 * Manages two execution modes for plugins:
 *
 *   1. Wasm / V8 Isolate (Modern):   Plugins marked "modern" in their
 *      blueprint.json run inside a WebAssembly or V8 isolate using
 *      ext-wasm or ext-v8js. This provides true memory and syscall
 *      isolation.
 *
 *   2. Virtual PHP Namespace (Legacy):  Legacy plugins are wrapped in a
 *      dynamic namespace at runtime via stream_wrapper-based code
 *      transformation. Global scope pollution is prevented through
 *      scope isolation.
 *
 * The IsolateManager handles the context-switch lifecycle: enter,
 * snapshot, leave — called by the HookMarshaller for each callback.
 *
 * @package Axiom\Kernel
 */

declare(strict_types=1);

namespace Axiom\Kernel;

use Axiom\Bridge\StateSnapshotEngine;
use Axiom\Security\ManifestValidator;
use Axiom\Security\ResourceGovernor;
use Axiom\Security\ResourceExhaustedException;
use Axiom\Profiler\AuditLogger;
use Axiom\Profiler\AutomatedProfiler;

final class IsolateManager
{
    private KernelConfig $config;
    private ManifestValidator $manifest_validator;
    private StateSnapshotEngine $snapshot_engine;
    private ResourceGovernor $resource_governor;
    private AuditLogger $logger;
    private ?AutomatedProfiler $profiler;

    /**
     * Currently active isolates per plugin slug.
     * @var array<string, bool>
     */
    private array $active_isolates = [];

    /**
     * Nesting depth of isolate entry per plugin.
     * @var array<string, int>
     */
    private array $isolate_depth = [];

    /**
     * Registered namespace wrappers (stream wrapper instances).
     * @var array<string, NamespaceWrapper>
     */
    private array $namespace_wrappers = [];

    /**
     * Was this isolate manager initialized with a Wasm engine?
     */
    private bool $wasm_available = false;

    public function __construct(
        KernelConfig $config,
        ManifestValidator $manifest_validator,
        StateSnapshotEngine $snapshot_engine,
        ResourceGovernor $resource_governor,
        ?AuditLogger $logger = null,
        ?AutomatedProfiler $profiler = null
    ) {
        $this->config             = $config;
        $this->manifest_validator = $manifest_validator;
        $this->snapshot_engine    = $snapshot_engine;
        $this->resource_governor  = $resource_governor;
        $this->logger             = $logger ?? new AuditLogger( $config );
        $this->profiler           = $profiler;

        $this->wasm_available = $this->detect_wasm_runtime();
    }

    /**
     * Enter a plugin's isolate context for the duration of a hook callback.
     *
     * @param string $plugin_slug The plugin slug.
     * @param string $hook_name   The hook being executed.
     */
    public function enter( string $plugin_slug, string $hook_name ): void
    {
        $context = Kernel::get_instance()->get_plugin_context( $plugin_slug );
        if ( $context === null ) {
            return;
        }

        $depth = $this->isolate_depth[ $plugin_slug ] ?? 0;
        $this->isolate_depth[ $plugin_slug ] = $depth + 1;

        if ( $depth === 0 ) {
            $this->active_isolates[ $plugin_slug ] = true;

            if ( $context->is_modern() && $this->wasm_available ) {
                $this->enter_wasm_isolate( $context, $hook_name );
            } else {
                $this->enter_namespace_isolate( $context, $hook_name );
            }
        }

        Kernel::get_instance()->database_proxy()->push_plugin( $plugin_slug );
    }

    /**
     * Leave a plugin's isolate context.
     */
    public function leave( string $plugin_slug ): void
    {
        $depth = $this->isolate_depth[ $plugin_slug ] ?? 0;
        if ( $depth <= 1 ) {
            unset( $this->active_isolates[ $plugin_slug ] );
            unset( $this->isolate_depth[ $plugin_slug ] );
        } else {
            $this->isolate_depth[ $plugin_slug ] = $depth - 1;
        }

        Kernel::get_instance()->database_proxy()->pop_plugin();
    }

    /**
     * Capture a state snapshot before plugin execution.
     */
    public function snapshot_state(): array
    {
        return $this->snapshot_engine->snapshot();
    }

    /**
     * Sync back state after plugin execution.
     */
    public function sync_back_state( array $snapshot, string $plugin_slug ): void
    {
        $modified = [];
        foreach ( StateSnapshotEngine::TRACKED_GLOBALS as $key ) {
            if ( array_key_exists( $key, $GLOBALS ) ) {
                $current = $GLOBALS[ $key ];
                $saved   = $snapshot[ $key ] ?? null;
                if ( $current !== $saved ) {
                    $modified[ $key ] = $current;
                }
            }
        }
        $this->snapshot_engine->sync_back( $modified, $plugin_slug );
    }

    /**
     * Begin resource monitoring for the current plugin.
     */
    public function begin_resource_monitoring(): void
    {
        $plugin_slug = Kernel::get_instance()->database_proxy()->current_plugin();
        if ( $plugin_slug === null ) {
            return;
        }

        $context = Kernel::get_instance()->get_plugin_context( $plugin_slug );
        if ( $context !== null ) {
            $this->resource_governor->begin( $context );
        }
    }

    /**
     * End resource monitoring.
     */
    public function end_resource_monitoring(): void
    {
        $this->resource_governor->end();
    }

    /**
     * Enter a Wasm/V8 isolate (modern plugins).
     */
    private function enter_wasm_isolate( PluginContext $context, string $hook_name ): void
    {
        $this->logger->log( AuditLogger::INFO, 'Entering Wasm isolate', [
            'plugin' => $context->slug(),
            'hook'   => $hook_name,
        ] );
    }

    /**
     * Enter a virtual PHP namespace isolate (legacy plugins).
     *
     * For legacy plugins, we use a stream_wrapper that transparently
     * rewrites PHP code to wrap it in a unique namespace, preventing
     * global class/function collisions.
     */
    private function enter_namespace_isolate( PluginContext $context, string $hook_name ): void
    {
        $slug = $context->slug();

        if ( ! isset( $this->namespace_wrappers[ $slug ] ) ) {
            $wrapper = new NamespaceWrapper( $slug );
            $this->namespace_wrappers[ $slug ] = $wrapper;
        }

        $this->logger->log( AuditLogger::INFO, 'Entering namespace isolate', [
            'plugin' => $slug,
            'hook'   => $hook_name,
        ] );
    }

    /**
     * Register a NamespaceWrapper streamWrapper for a given plugin slug.
     *
     * The wrapper intercepts include/require calls originating from the
     * plugin's directory and dynamically rewrites the PHP to namespace it.
     */
    public function register_namespace_wrapper( string $plugin_slug, string $plugin_dir ): void
    {
        $wrapper = new NamespaceWrapper( $plugin_slug, $plugin_dir );
        $this->namespace_wrappers[ $plugin_slug ] = $wrapper;
    }

    /**
     * Check if ext-wasm or ext-v8js is available.
     */
    private function detect_wasm_runtime(): bool
    {
        if ( ! $this->config->enable_wasm() ) {
            return false;
        }
        return extension_loaded( 'wasm' ) || extension_loaded( 'v8js' );
    }

    /**
     * Check if a plugin isolate is currently active.
     */
    public function is_active( string $plugin_slug ): bool
    {
        return isset( $this->active_isolates[ $plugin_slug ] );
    }

    /**
     * Get the current nesting depth for a plugin.
     */
    public function depth( string $plugin_slug ): int
    {
        return $this->isolate_depth[ $plugin_slug ] ?? 0;
    }

    /**
     * Get the count of currently active isolates.
     */
    public function active_count(): int
    {
        return count( $this->active_isolates );
    }
}
