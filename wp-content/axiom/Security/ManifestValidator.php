<?php
/**
 * Manifest Validator — Capability-Based Access Control
 *
 * Loads and validates plugin blueprint.json manifests, caches them,
 * and provides the check() interface that every Axiom security gate
 * calls to verify a specific capability before granting access.
 *
 * In learning mode, unknown capabilities are logged rather than blocked.
 *
 * @package Axiom\Security
 */

declare(strict_types=1);

namespace Axiom\Security;

use Axiom\Kernel\KernelConfig;
use Axiom\Profiler\AuditLogger;

final class ManifestValidator
{
    private KernelConfig $config;
    private AuditLogger $logger;

    /**
     * @var array<string, PluginManifest> Cached manifests keyed by plugin slug.
     */
    private array $manifest_cache = [];

    public function __construct( KernelConfig $config, ?AuditLogger $logger = null )
    {
        $this->config = $config;
        $this->logger = $logger ?? new AuditLogger( $config );
    }

    /**
     * Load (and cache) a plugin's blueprint.json manifest.
     *
     * Searches the plugin root, then the global manifests directory.
     * Returns null if no manifest exists (learn mode generates one later).
     */
    public function load_manifest( string $plugin_slug, string $plugin_file ): ?PluginManifest
    {
        if ( isset( $this->manifest_cache[ $plugin_slug ] ) ) {
            return $this->manifest_cache[ $plugin_slug ];
        }

        $search_paths = [
            dirname( $plugin_file ) . '/blueprint.json',
            $this->config->manifest_dir() . '/' . $plugin_slug . '.json',
        ];

        foreach ( $search_paths as $path ) {
            if ( file_exists( $path ) ) {
                $data = json_decode( file_get_contents( $path ), true );
                if ( json_last_error() === JSON_ERROR_NONE && $this->validate_structure( $data ) ) {
                    $manifest = new PluginManifest( $data );
                    $this->manifest_cache[ $plugin_slug ] = $manifest;
                    return $manifest;
                }
            }
        }

        return null;
    }

    /**
     * Reload a manifest from disk (used by profiler after generating one).
     */
    public function reload_manifest( string $plugin_slug, string $plugin_file ): ?PluginManifest
    {
        unset( $this->manifest_cache[ $plugin_slug ] );
        return $this->load_manifest( $plugin_slug, $plugin_file );
    }

    /**
     * Central capability check. The primary security gate.
     *
     * @param string      $plugin_slug Plugin requesting the capability.
     * @param string      $capability  Fully-qualified capability string (e.g. 'db:read:wp_posts').
     * @param string|null $resource    Optional resource qualifier (table name, file path, domain).
     *
     * @return bool True if permitted, false if denied.
     */
    public function check( string $plugin_slug, string $capability, ?string $resource = null ): bool
    {
        $manifest = $this->manifest_cache[ $plugin_slug ] ?? null;

        if ( $this->config->is_plugin_trusted( $plugin_slug ) ) {
            return true;
        }

        if ( $manifest === null ) {
            if ( $this->config->is_learning_mode() ) {
                $this->log_unknown_capability( $plugin_slug, $capability, $resource );
                return true;
            }
            return false;
        }

        $permitted = $this->evaluate( $manifest, $capability, $resource );

        if ( ! $permitted && $this->config->is_learning_mode() ) {
            $this->log_unknown_capability( $plugin_slug, $capability, $resource );
            return true;
        }

        if ( ! $permitted ) {
            $this->logger->log( AuditLogger::SECURITY, 'Capability denied', [
                'plugin'   => $plugin_slug,
                'cap'      => $capability,
                'resource' => $resource,
            ] );
        }

        return $permitted;
    }

    /**
     * Evaluate a capability against the manifest's permission tree.
     */
    private function evaluate( PluginManifest $manifest, string $capability, ?string $resource ): bool
    {
        $parts = explode( ':', $capability, 3 );

        switch ( $parts[0] ) {
            case 'db':
                $operation = $parts[1] ?? 'read';
                $table     = $resource ?? $parts[2] ?? '';
                return $manifest->can_access_table( $table, $operation );

            case 'filesystem':
                $operation = $parts[1] ?? 'read';
                $path      = $resource ?? '';
                return $manifest->can_access_filesystem( $path, $operation );

            case 'network':
                $domain = $resource ?? '';
                return $manifest->can_network_outbound( $domain );

            case 'wp':
                if ( ( $parts[1] ?? '' ) === 'hooks' ) {
                    $hook   = $resource ?? '';
                    $is_write = ( $parts[2] ?? 'read_only' ) === 'write';
                    return $manifest->can_subscribe_hook( $hook, $is_write );
                }
                if ( ( $parts[1] ?? '' ) === 'options' ) {
                    $option   = $resource ?? '';
                    $is_write = ( $parts[2] ?? 'read' ) === 'write';
                    return $is_write
                        ? $manifest->can_write_option( $option )
                        : $manifest->can_read_option( $option );
                }
                if ( ( $parts[1] ?? '' ) === 'users' ) {
                    $cap = $parts[2] ?? '';
                    return $manifest->can_read_user_data( $cap );
                }
                return false;

            case 'exec':
                return $manifest->can_exec();

            default:
                return false;
        }
    }

    /**
     * Log a god-mode event during learning mode.
     */
    private function log_unknown_capability( string $plugin_slug, string $capability, ?string $resource ): void
    {
        $this->logger->log( AuditLogger::LEARNING, 'Unknown capability (learning)', [
            'plugin'   => $plugin_slug,
            'cap'      => $capability,
            'resource' => $resource,
        ] );
    }

    /**
     * Validate the structural integrity of a raw manifest array.
     */
    private function validate_structure( $data ): bool
    {
        if ( ! \is_array( $data ) ) {
            return false;
        }
        if ( ! isset( $data['id'] ) || ! \is_string( $data['id'] ) ) {
            return false;
        }
        return true;
    }
}
