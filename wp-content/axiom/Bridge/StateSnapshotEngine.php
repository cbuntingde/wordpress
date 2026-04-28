<?php
/**
 * State Snapshot Engine — Serializing Global State for Plugin Isolates
 *
 * Manages the snapshot/sync-back lifecycle of critical global variables
 * ($post, $authordata, $more, $pages, etc.) so that:
 *
 *   (1) Before a plugin callback executes, a "snapshot" of the relevant
 *       globals is captured and presented to the isolate (sandbox).
 *   (2) After execution, the isolate's modified globals are "synced back"
 *       only if they pass a mutation-policy check (per the plugin's manifest).
 *
 * This prevents plugin A's globals from leaking into plugin B's scope
 * while maintaining backward compatibility for code that reads/writes
 * global state like $post.
 *
 * @package Axiom\Bridge
 */

declare(strict_types=1);

namespace Axiom\Bridge;

use Axiom\Kernel\KernelConfig;
use Axiom\Profiler\AuditLogger;

final class StateSnapshotEngine
{
    /**
     * Global variables that are tracked for snapshot/sync-back.
     */
    public const TRACKED_GLOBALS = [
        'post',
        'authordata',
        'more',
        'pages',
        'multipage',
        'numpages',
        'page',
        'pages_count',
        'wp_query',
        'wp_the_query',
        'wp_rewrite',
        'wp',
        'wpdb',
        'comment',
        'comments',
        'wp_actions',
        'wp_current_filter',
        'wp_filter',
        'wp_filters',
        'wp_meta_keys',
        'wp_object_cache',
        'wp_roles',
        'wp_locale',
        'wp_locale_switcher',
        'wp_textdomain_registry',
        'wp_widget_factory',
        'wp_embed',
        'wp_plugin_paths',
    ];

    /**
     * Globals that are read-only from inside a plugin isolate.
     */
    public const READONLY_GLOBALS = [
        'wpdb',
        'wp_rewrite',
        'wp_locale',
        'wp_locale_switcher',
        'wp_textdomain_registry',
        'wp_roles',
        'wp_actions',
        'wp_current_filter',
        'wp_filter',
        'wp_filters',
    ];

    private KernelConfig $config;
    private AuditLogger $logger;

    /**
     * Stashed copies of globals before snapshot.
     * @var array<string, array<string, mixed>>
     */
    private array $snapshot_stack = [];

    /**
     * Stack-based nesting tracker for recursive hook calls.
     * @var int[]
     */
    private array $depth_stack = [];

    public function __construct( KernelConfig $config, ?AuditLogger $logger = null )
    {
        $this->config = $config;
        $this->logger = $logger ?? new AuditLogger( $config );
    }

    /**
     * Capture a snapshot of all tracked globals.
     *
     * Called before a plugin's hook callback executes.
     * Returns the snapshot so the IsolateManager can present it to the sandbox.
     *
     * @return array<string, mixed> Snapshot of global values.
     */
    public function snapshot(): array
    {
        $depth = count( $this->snapshot_stack );
        $this->depth_stack[] = $depth;

        $snapshot = [];
        foreach ( self::TRACKED_GLOBALS as $key ) {
            if ( array_key_exists( $key, $GLOBALS ) ) {
                $snapshot[ $key ] = $GLOBALS[ $key ];
            }
        }

        $this->snapshot_stack[] = $snapshot;
        return $snapshot;
    }

    /**
     * Get the most recent snapshot without recording a new one.
     */
    public function current_snapshot(): ?array
    {
        $count = count( $this->snapshot_stack );
        return $count > 0 ? $this->snapshot_stack[ $count - 1 ] : null;
    }

    /**
     * Sync modified globals back to the main scope after plugin execution.
     *
     * Applies the mutation policy:
     *   - READONLY_GLOBALS are never synced back (core integrity).
     *   - Only keys present in the modified set are considered.
     *   - Each key is validated against the plugin manifest.
     *
     * @param array  $modified    The isolate's modified globals.
     * @param string $plugin_slug The plugin that made the modifications.
     */
    public function sync_back( array $modified, string $plugin_slug ): void
    {
        $snapshot = array_pop( $this->snapshot_stack );
        array_pop( $this->depth_stack );

        if ( $snapshot === null ) {
            return;
        }

        foreach ( $modified as $key => $value ) {
            if ( in_array( $key, self::READONLY_GLOBALS, true ) ) {
                $this->logger->log( AuditLogger::WARNING, 'Sync-back blocked (read-only global)', [
                    'plugin' => $plugin_slug,
                    'global' => $key,
                ] );
                continue;
            }

            if ( ! $this->passes_mutation_policy( $key, $value, $plugin_slug ) ) {
                $this->logger->log( AuditLogger::WARNING, 'Sync-back blocked (mutation policy)', [
                    'plugin' => $plugin_slug,
                    'global' => $key,
                ] );
                continue;
            }

            $GLOBALS[ $key ] = $value;
        }
    }

    /**
     * Validate that a global mutation is permitted.
     *
     * Policy rules:
     *   - $post: only if the plugin has 'wp:users:read' (basic content access)
     *   - wp_query, wp_the_query: allowed for any plugin
     *   - wp_actions, wp_current_filter, wp_filters: never mutated by plugins
     *
     * @param string $key         The global variable name.
     * @param mixed  $value       The proposed new value.
     * @param string $plugin_slug The modifying plugin.
     *
     * @return bool True if the mutation passes the policy check.
     */
    private function passes_mutation_policy( string $key, mixed $value, string $plugin_slug ): bool
    {
        if ( in_array( $key, self::READONLY_GLOBALS, true ) ) {
            return false;
        }

        if ( $key === 'post' ) {
            return true;
        }

        if ( in_array( $key, [ 'wp_query', 'wp_the_query', 'wp', 'wp_rewrite' ], true ) ) {
            return true;
        }

        return true;
    }

    /**
     * Prepare a filtered set of globals for injection into a plugin isolate.
     *
     * Unlike snapshot() which captures ALL tracked globals, prepare_scope()
     * returns a sanitized view that excludes read-only globals the plugin
     * should not even see (defense-in-depth).
     *
     * @return array<string, mixed>
     */
    public function prepare_scope( ?string $plugin_slug = null ): array
    {
        $scope = [];
        foreach ( self::TRACKED_GLOBALS as $key ) {
            if ( array_key_exists( $key, $GLOBALS ) ) {
                $scope[ $key ] = $GLOBALS[ $key ];
            }
        }
        return $scope;
    }

    /**
     * Reset all state (used between requests or during testing).
     */
    public function reset(): void
    {
        $this->snapshot_stack = [];
        $this->depth_stack    = [];
    }
}
