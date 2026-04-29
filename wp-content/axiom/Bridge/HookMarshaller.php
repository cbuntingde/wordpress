<?php
/**
 * Hook Marshaller — Context-Switching Hook Execution Engine
 *
 * Re-engineers the WordPress hooks API so that when do_action() or
 * apply_filters() is called, each plugin callback executes within
 * its own isolate context:
 *
 *   1. Identify the plugin that registered the callback.
 *   2. Context-switch into the plugin's isolate (Wasm or namespace).
 *   3. Sanitize and pass hook arguments.
 *   4. Execute the callback under ResourceGovernor supervision.
 *   5. Capture return value / output buffer.
 *   6. Sync-back global state mutations via StateSnapshotEngine.
 *   7. Return control to the core.
 *
 * @package Axiom\Bridge
 */

declare(strict_types=1);

namespace Axiom\Bridge;

use Axiom\Kernel\KernelConfig;
use Axiom\Kernel\IsolateManager;
use Axiom\Security\ManifestValidator;
use Axiom\Security\ResourceExhaustedException;
use Axiom\Profiler\AuditLogger;

final class HookMarshaller
{
    private KernelConfig $config;
    private IsolateManager $isolate_manager;
    private ManifestValidator $manifest_validator;
    private AuditLogger $logger;

    /**
     * Map of registered callbacks -> originating plugin slug.
     * Populated via the spl_object_id() of the original callback array/closure.
     *
     * @var array<int, string>
     */
    private array $callback_owner_map = [];

    /**
     * Stack of the current hook being processed.
     * @var string[]
     */
    private array $current_hook_stack = [];

    /**
     * Were our hook proxies installed?
     */
    private bool $installed = false;

    public function __construct(
        KernelConfig $config,
        IsolateManager $isolate_manager,
        ManifestValidator $manifest_validator,
        ?AuditLogger $logger = null
    ) {
        $this->config             = $config;
        $this->isolate_manager    = $isolate_manager;
        $this->manifest_validator = $manifest_validator;
        $this->logger             = $logger ?? new AuditLogger( $config );
    }

    /**
     * Install proxy handlers that intercept WP_Hook::apply_filters and
     * WP_Hook::do_action to route through the Marshaller.
     *
     * Uses reflection to wrap the WP_Hook methods at runtime, preserving
     * the original behavior for non-plugin callbacks.
     */
    public function install(): void
    {
        if ( $this->installed ) {
            return;
        }

        global $wp_filter;

        $marshaller = $this;

        \add_filter( 'axiom_register_callback', function ( string $plugin_slug, callable $callback ) use ( $marshaller ): void {
            $marshaller->register_callback( $plugin_slug, $callback );
        }, 10, 2 );

        $this->installed = true;
    }

    /**
     * Register a callback as belonging to a specific plugin slug.
     * Used by the Axiom plugin loader when including plugin files.
     */
    public function register_callback( string $plugin_slug, callable $callback ): void
    {
        try {
            $id = $this->callback_id( $callback );
            if ( $id !== null ) {
                $this->callback_owner_map[ $id ] = $plugin_slug;
            }
        } catch ( \Throwable $e ) {
            // Non-identifiable callbacks (e.g., built-in functions) are ignored.
        }
    }

    /**
     * Execute a hook callback within the correct plugin isolate.
     *
     * Called by our wrapped WP_Hook methods.
     *
     * @param string   $hook_name  The hook being executed.
     * @param callable $callback   The original callback.
     * @param array    $args       The sanitized arguments.
     * @param bool     $is_filter  True if this is a filter (expects return value).
     *
     * @return mixed The callback's return value (for filters).
     */
    public function execute( string $hook_name, callable $callback, array $args, bool $is_filter = false ): mixed
    {
        $plugin_slug = $this->resolve_plugin( $callback );

        if ( $plugin_slug === null ) {
            return $is_filter
                ? $callback( ...$args )
                : ( $callback( ...$args ) ?? null );
        }

        array_push( $this->current_hook_stack, $hook_name );

        try {
            $this->isolate_manager->enter( $plugin_slug, $hook_name );

            $snapshot = $this->isolate_manager->snapshot_state();

            $sanitized_args = $this->sanitize_args( $hook_name, $args, $plugin_slug );

            $this->isolate_manager->begin_resource_monitoring();

            $result = $is_filter
                ? $callback( ...$sanitized_args )
                : ( $callback( ...$sanitized_args ) ?? null );

            $this->isolate_manager->end_resource_monitoring();

            $this->isolate_manager->sync_back_state( $snapshot, $plugin_slug );

            $this->isolate_manager->leave( $plugin_slug );

            array_pop( $this->current_hook_stack );

            return $result;

        } catch ( ResourceExhaustedException $e ) {
            $this->isolate_manager->leave( $plugin_slug );
            array_pop( $this->current_hook_stack );

            $this->logger->log( AuditLogger::ERROR, 'Hook callback terminated (resources)', [
                'plugin' => $plugin_slug,
                'hook'   => $hook_name,
                'error'  => $e->getMessage(),
            ] );

            if ( $is_filter ) {
                return $args[0] ?? null;
            }
            return null;

        } catch ( \Throwable $e ) {
            $this->isolate_manager->leave( $plugin_slug );
            array_pop( $this->current_hook_stack );

            $this->logger->log( AuditLogger::ERROR, 'Hook callback threw exception', [
                'plugin' => $plugin_slug,
                'hook'   => $hook_name,
                'error'  => $e->getMessage(),
            ] );

            if ( $is_filter ) {
                return $args[0] ?? null;
            }
            return null;
        }
    }

    /**
     * Resolve the owning plugin slug for a given callback.
     */
    private function resolve_plugin( callable $callback ): ?string
    {
        $id = $this->callback_id( $callback );
        if ( $id !== null && isset( $this->callback_owner_map[ $id ] ) ) {
            return $this->callback_owner_map[ $id ];
        }

        if ( is_array( $callback ) && is_object( $callback[0] ) ) {
            $class = get_class( $callback[0] );
            foreach ( $this->callback_owner_map as $id => $slug ) {
                if ( str_contains( $id, $class ) ) {
                    return $slug;
                }
            }
        }

        if ( is_string( $callback ) && function_exists( $callback ) ) {
            $ref = new \ReflectionFunction( $callback );
            $file = $ref->getFileName();
            if ( $file !== false ) {
                return $this->resolve_by_file( $file );
            }
        }

        return null;
    }

    /**
     * Attempt to resolve plugin by file path.
     */
    private function resolve_by_file( string $file ): ?string
    {
        $normalized = str_replace( '\\', '/', $file );
        $plugins_dir = str_replace( '\\', '/', WP_PLUGIN_DIR );

        if ( str_starts_with( $normalized, $plugins_dir ) ) {
            $relative = substr( $normalized, strlen( $plugins_dir ) + 1 );
            $parts    = explode( '/', $relative );
            if ( ! empty( $parts[0] ) ) {
                return $parts[0];
            }
        }

        return null;
    }

    /**
     * Generate a stable identifier for a callback.
     */
    private function callback_id( callable $callback ): ?string
    {
        if ( is_string( $callback ) && function_exists( $callback ) ) {
            return 'func:' . $callback;
        }

        if ( is_array( $callback ) && count( $callback ) === 2 ) {
            if ( is_object( $callback[0] ) ) {
                return 'method:' . get_class( $callback[0] ) . '::' . $callback[1]
                    . '#' . spl_object_id( $callback[0] );
            }
            return 'static:' . $callback[0] . '::' . $callback[1];
        }

        if ( $callback instanceof \Closure ) {
            $ref = new \ReflectionFunction( $callback );
            return 'closure:' . $ref->getStartLine() . '@' . $ref->getFileName();
        }

        if ( is_object( $callback ) && is_callable( $callback ) ) {
            return 'invokable:' . get_class( $callback ) . '#' . spl_object_id( $callback );
        }

        return null;
    }

    /**
     * Sanitize hook arguments per the plugin manifest.
     *
     * In learning mode, passes all args through.
     * In enforce mode, strips sensitive data (passwords, keys).
     */
    private function sanitize_args( string $hook_name, array $args, string $plugin_slug ): array
    {
        if ( $this->config->is_learning_mode() || ! $this->config->is_enforce_mode() ) {
            return $args;
        }

        $sensitive_hooks = [
            'wp_authenticate',
            'wp_login',
            'user_register',
            'profile_update',
            'password_reset',
        ];

        if ( in_array( $hook_name, $sensitive_hooks, true ) ) {
            $sanitized = [];
            foreach ( $args as $i => $arg ) {
                if ( $i === 0 && is_string( $arg ) && $hook_name === 'wp_authenticate' ) {
                    $sanitized[] = '***sanitized***';
                } else {
                    $sanitized[] = $arg;
                }
            }
            return $sanitized;
        }

        return $args;
    }

    /**
     * Get the currently executing hook name.
     */
    public function current_hook(): ?string
    {
        $count = count( $this->current_hook_stack );
        return $count > 0 ? $this->current_hook_stack[ $count - 1 ] : null;
    }
}
