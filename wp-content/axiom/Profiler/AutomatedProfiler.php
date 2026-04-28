<?php
/**
 * Automated Profiler — Legacy Learning Mode
 *
 * When Axiom is in "learning mode," the AutomatedProfiler watches all
 * plugin activity. Every attempted "god-mode" action (SQL query touching
 * an undeclared table, filesystem access outside declared paths, network
 * requests to unknown domains) is recorded.
 *
 * At the end of the observation window, the profiler generates a draft
 * blueprint.json manifest that the site admin can review and approve.
 *
 * This enables a smooth onboarding path: install any legacy plugin,
 * run it in learning mode, auto-generate its manifest, then switch
 * to enforce mode.
 *
 * @package Axiom\Profiler
 */

declare(strict_types=1);

namespace Axiom\Profiler;

use Axiom\Kernel\KernelConfig;

final class AutomatedProfiler
{
    private KernelConfig $config;
    private AuditLogger $logger;

    /**
     * Accumulated god-mode actions per plugin.
     * @var array<string, array<int, array>>
     */
    private array $plugin_actions = [];

    /**
     * Plugins currently under observation.
     * @var array<string, string>
     */
    private array $watched_plugins = [];

    /**
     * Observation start time (microseconds).
     */
    private float $observation_start;

    public function __construct( KernelConfig $config, AuditLogger $logger )
    {
        $this->config            = $config;
        $this->logger            = $logger;
        $this->observation_start = microtime( true );
    }

    /**
     * Begin profiling a plugin.
     */
    public function watch_plugin( string $plugin_slug, string $plugin_file ): void
    {
        if ( ! isset( $this->watched_plugins[ $plugin_slug ] ) ) {
            $this->watched_plugins[ $plugin_slug ] = $plugin_file;
            $this->plugin_actions[ $plugin_slug ]  = [];

            $this->logger->log( AuditLogger::LEARNING, 'Profiler watching plugin', [
                'plugin' => $plugin_slug,
                'file'   => $plugin_file,
            ] );
        }
    }

    /**
     * Record a god-mode action for profiling.
     *
     * @param string $plugin_slug The plugin that performed the action.
     * @param array  $action      Action details: type, resource, operation, etc.
     */
    public function record_god_mode_action( string $plugin_slug, array $action ): void
    {
        if ( ! isset( $this->plugin_actions[ $plugin_slug ] ) ) {
            return;
        }

        $action['_count'] = 1;
        $action['_first_seen'] = gmdate( 'Y-m-d\TH:i:s\Z' );

        $hash = md5( json_encode( $action ) );
        if ( isset( $this->plugin_actions[ $plugin_slug ][ $hash ] ) ) {
            $this->plugin_actions[ $plugin_slug ][ $hash ]['_count']++;
        } else {
            $this->plugin_actions[ $plugin_slug ][ $hash ] = $action;
        }
    }

    /**
     * Generate a draft blueprint.json for a profiled plugin.
     *
     * Analyzes all recorded god-mode actions and produces a manifest
     * that covers the observed access patterns.
     *
     * @param string $plugin_slug
     *
     * @return array|null The draft manifest, or null if no data.
     */
    public function generate_manifest( string $plugin_slug ): ?array
    {
        if ( empty( $this->plugin_actions[ $plugin_slug ] ) ) {
            return null;
        }

        $actions = $this->plugin_actions[ $plugin_slug ];

        $manifest = [
            'id'               => $plugin_slug,
            'name'             => $plugin_slug,
            'manifest_version' => '1.0',
            'isolation'        => 'namespace',
            'permissions'      => [
                'db'         => [
                    'read'   => [],
                    'write'  => [],
                    'delete' => [],
                    'alter'  => [],
                ],
                'filesystem' => [],
                'network'    => [
                    'outbound' => [],
                ],
                'wp'         => [
                    'hooks'   => [
                        'read_only' => [],
                        'write'     => [],
                    ],
                    'options' => [
                        'read'  => [],
                        'write' => [],
                    ],
                    'users'   => [
                        'read' => [],
                    ],
                ],
                'system'     => [],
            ],
            'resource_limits'  => [
                'cpu_ms'    => $this->config->cpu_limit_ms(),
                'memory_mb' => $this->config->memory_limit_mb(),
            ],
            '_generated'       => gmdate( 'Y-m-d\TH:i:s\Z' ),
            '_observation_sec' => round( microtime( true ) - $this->observation_start, 2 ),
            '_action_count'    => count( $actions ),
        ];

        $seen_tables_read   = [];
        $seen_tables_write  = [];
        $seen_tables_delete = [];
        $seen_tables_alter  = [];
        $seen_filesystem    = [];
        $seen_network       = [];

        foreach ( $actions as $hash => $action ) {
            $type = $action['type'] ?? '';

            switch ( $type ) {
                case 'sql':
                    $table  = $action['table'] ?? '';
                    $op     = $action['action'] ?? 'read';
                    if ( $table !== '' ) {
                        switch ( $op ) {
                            case 'read':
                                $seen_tables_read[ $table ] = true;
                                break;
                            case 'write':
                                $seen_tables_write[ $table ] = true;
                                break;
                            case 'delete':
                                $seen_tables_delete[ $table ] = true;
                                break;
                            case 'alter':
                                $seen_tables_alter[ $table ] = true;
                                break;
                        }
                    }
                    break;

                case 'filesystem':
                    $path = $action['path'] ?? '';
                    if ( $path !== '' && ! in_array( $path, $seen_filesystem, true ) ) {
                        $seen_filesystem[] = $path;
                    }
                    break;

                case 'network':
                    $domain = $action['domain'] ?? '';
                    if ( $domain !== '' && ! in_array( $domain, $seen_network, true ) ) {
                        $seen_network[] = $domain;
                    }
                    break;

                case 'hook':
                    $hook = $action['hook'] ?? '';
                    if ( $hook !== '' ) {
                        $manifest['permissions']['wp']['hooks']['read_only'][] = $hook;
                    }
                    break;
            }
        }

        $manifest['permissions']['db']['read']   = array_keys( $seen_tables_read );
        $manifest['permissions']['db']['write']  = array_keys( $seen_tables_write );
        $manifest['permissions']['db']['delete'] = array_keys( $seen_tables_delete );
        $manifest['permissions']['db']['alter']  = array_keys( $seen_tables_alter );
        $manifest['permissions']['filesystem']   = $seen_filesystem;
        $manifest['permissions']['network']['outbound'] = $seen_network;

        return $manifest;
    }

    /**
     * Write a generated manifest to disk.
     *
     * @param string $plugin_slug
     *
     * @return string|null The manifest file path, or null on failure.
     */
    public function write_manifest( string $plugin_slug ): ?string
    {
        $manifest = $this->generate_manifest( $plugin_slug );
        if ( $manifest === null ) {
            return null;
        }

        $manifest_dir = $this->config->manifest_dir();
        if ( ! is_dir( $manifest_dir ) ) {
            wp_mkdir_p( $manifest_dir );
        }

        $file = $manifest_dir . '/' . $plugin_slug . '.json';
        $json = json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

        if ( file_put_contents( $file, $json, LOCK_EX ) !== false ) {
            $this->logger->log( AuditLogger::INFO, 'Profiler generated draft manifest', [
                'plugin' => $plugin_slug,
                'file'   => $file,
            ] );
            return $file;
        }

        return null;
    }

    /**
     * Get all profiled actions for a plugin.
     */
    public function get_actions( string $plugin_slug ): array
    {
        return $this->plugin_actions[ $plugin_slug ] ?? [];
    }

    /**
     * Get the list of watched plugins.
     */
    public function watched_plugins(): array
    {
        return array_keys( $this->watched_plugins );
    }

    /**
     * Generate manifests for all watched plugins.
     *
     * @return array<string, string> Map of plugin slug -> manifest file path.
     */
    public function generate_all_manifests(): array
    {
        $results = [];
        foreach ( $this->watched_plugins as $slug => $file ) {
            $path = $this->write_manifest( $slug );
            if ( $path !== null ) {
                $results[ $slug ] = $path;
            }
        }
        return $results;
    }

    /**
     * Reset all profiled data (for starting a fresh observation).
     */
    public function reset(): void
    {
        $this->plugin_actions    = [];
        $this->watched_plugins   = [];
        $this->observation_start = microtime( true );
    }
}
