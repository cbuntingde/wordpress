<?php
/**
 * Manifest Generator — Produces blueprint.json from Profiler Data
 *
 * Standalone utility that converts profiler observations into
 * a valid blueprint.json manifest. Used by the AutomatedProfiler
 * and also callable independently for manual manifest authoring.
 *
 * @package Axiom\Profiler
 */

declare(strict_types=1);

namespace Axiom\Profiler;

final class ManifestGenerator
{
    /**
     * Build an empty manifest skeleton for a plugin.
     */
    public static function skeleton( string $plugin_slug, string $plugin_name = '' ): array
    {
        return [
            'id'               => $plugin_slug,
            'name'             => $plugin_name ?: $plugin_slug,
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
                'cpu_ms'    => 500,
                'memory_mb' => 64,
            ],
        ];
    }

    /**
     * Write a manifest to disk.
     *
     * @param array  $manifest The manifest data structure.
     * @param string $file     Target file path.
     *
     * @return bool True on success.
     */
    public static function write( array $manifest, string $file ): bool
    {
        $dir = dirname( $file );
        if ( ! is_dir( $dir ) ) {
            wp_mkdir_p( $dir );
        }

        $json = json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        return file_put_contents( $file, $json, LOCK_EX ) !== false;
    }

    /**
     * Validate a manifest file for structural correctness.
     *
     * @param string $file Path to the blueprint.json.
     *
     * @return array{valid: bool, errors: string[]}
     */
    public static function validate( string $file ): array
    {
        $errors = [];

        if ( ! file_exists( $file ) ) {
            return [ 'valid' => false, 'errors' => [ 'File not found' ] ];
        }

        $data = json_decode( file_get_contents( $file ), true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            return [ 'valid' => false, 'errors' => [ 'Invalid JSON: ' . json_last_error_msg() ] ];
        }

        if ( empty( $data['id'] ) ) {
            $errors[] = 'Missing required field: id';
        }
        if ( empty( $data['manifest_version'] ) ) {
            $errors[] = 'Missing required field: manifest_version';
        }

        return [
            'valid'  => count( $errors ) === 0,
            'errors' => $errors,
        ];
    }
}
