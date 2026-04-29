<?php
/**
 * Audit Logger — Structured Security and Event Logging
 *
 * Provides a centralized logging service for all Axiom Kernel subsystems.
 * Logs are written to the audit log file and can optionally be sent
 * to WordPress debug.log (when WP_DEBUG is enabled).
 *
 * Supports severity levels: DEBUG, INFO, WARNING, ERROR, SECURITY, LEARNING.
 *
 * @package Axiom\Profiler
 */

declare(strict_types=1);

namespace Axiom\Profiler;

use Axiom\Kernel\KernelConfig;

final class AuditLogger
{
    public const DEBUG    = 'debug';
    public const INFO     = 'info';
    public const WARNING  = 'warning';
    public const ERROR    = 'error';
    public const SECURITY = 'security';
    public const LEARNING = 'learning';

    private KernelConfig $config;
    private string $log_file;
    private array $buffer = [];

    private const LEVEL_ORDER = [
        'debug'    => 0,
        'info'     => 1,
        'learning' => 2,
        'warning'  => 3,
        'error'    => 4,
        'security' => 5,
    ];

    public function __construct( KernelConfig $config )
    {
        $this->config  = $config;
        $this->log_file = WP_CONTENT_DIR . '/axiom/audit-' . gmdate( 'Y-m-d' ) . '.log';

        $log_dir = dirname( $this->log_file );
        if ( ! is_dir( $log_dir ) ) {
            \wp_mkdir_p( $log_dir );
        }

        register_shutdown_function( [ $this, 'flush' ] );
    }

    /**
     * Log a structured event.
     *
     * @param string $level    One of the class constants.
     * @param string $message  Human-readable event summary.
     * @param array  $context  Structured data payload.
     */
    public function log( string $level, string $message, array $context = [] ): void
    {
        $configured_level = self::LEVEL_ORDER[ $this->config->log_level() ] ?? self::LEVEL_ORDER['warning'];
        $event_level      = self::LEVEL_ORDER[ $level ] ?? 0;

        if ( $event_level < $configured_level ) {
            return;
        }

        $entry = [
            'timestamp' => gmdate( 'Y-m-d\TH:i:s.u\Z' ),
            'level'     => $level,
            'message'   => $message,
            'context'   => $context,
            'memory'    => memory_get_usage( true ),
            'request'   => $this->get_request_uri(),
        ];

        $this->buffer[] = $entry;

        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $this->write_debug_log( $entry );
        }
    }

    /**
     * Flush the log buffer to disk.
     */
    public function flush(): void
    {
        if ( empty( $this->buffer ) ) {
            return;
        }

        $lines = [];
        foreach ( $this->buffer as $entry ) {
            $lines[] = json_encode( $entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        }

        $content = implode( "\n", $lines ) . "\n";

        $handle = @fopen( $this->log_file, 'ab' );
        if ( $handle !== false ) {
            flock( $handle, LOCK_EX );
            fwrite( $handle, $content );
            flock( $handle, LOCK_UN );
            fclose( $handle );
        }

        $this->buffer = [];
    }

    /**
     * Destructor ensures log flush.
     */
    public function __destruct()
    {
        $this->flush();
    }

    /**
     * Write a single entry to WP debug.log.
     */
    private function write_debug_log( array $entry ): void
    {
        $line = sprintf(
            '[Axiom][%s] %s: %s',
            strtoupper( $entry['level'] ),
            $entry['message'],
            \wp_json_encode( $entry['context'] )
        );
        error_log( $line );
    }

    /**
     * Safely get the current request URI (or CLI marker).
     */
    private function get_request_uri(): string
    {
        if ( PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ) {
            return 'cli:' . ( $_SERVER['argv'][0] ?? 'unknown' );
        }
        return \wp_unslash( $_SERVER['REQUEST_URI'] ?? '/' );
    }
}
