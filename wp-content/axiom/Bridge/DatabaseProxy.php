<?php
/**
 * Database Proxy — Transparent $wpdb SQL Interception
 *
 * Wraps the global $wpdb instance with a Proxy_WPDB class that
 * intercepts every SQL query, lexes it to determine the target
 * tables and operation type, and checks each against the calling
 * plugin's blueprint.json manifest.
 *
 * In audit/learning mode, violations are logged but queries proceed.
 * In enforce mode, violating queries are blocked with wp_die().
 *
 * @package Axiom\Bridge
 */

declare(strict_types=1);

namespace Axiom\Bridge;

use Axiom\Kernel\KernelConfig;
use Axiom\Security\ManifestValidator;
use Axiom\Profiler\AuditLogger;
use Axiom\Profiler\AutomatedProfiler;

final class DatabaseProxy
{
    private KernelConfig $config;
    private ManifestValidator $manifest_validator;
    private AuditLogger $logger;
    private ?AutomatedProfiler $profiler;
    private ?string $current_plugin_slug = null;

    /**
     * Tracks which plugin is currently executing for SQL attribution.
     */
    private array $plugin_stack = [];

    public function __construct(
        KernelConfig $config,
        ManifestValidator $manifest_validator,
        ?AuditLogger $logger = null,
        ?AutomatedProfiler $profiler = null
    ) {
        $this->config             = $config;
        $this->manifest_validator = $manifest_validator;
        $this->logger             = $logger ?? new AuditLogger( $config );
        $this->profiler           = $profiler;
    }

    /**
     * Push a plugin onto the execution stack (called by HookMarshaller).
     */
    public function push_plugin( string $plugin_slug ): void
    {
        array_push( $this->plugin_stack, $plugin_slug );
    }

    /**
     * Pop the current plugin from the execution stack.
     */
    public function pop_plugin(): void
    {
        array_pop( $this->plugin_stack );
    }

    /**
     * Get the currently active plugin slug from the execution stack.
     */
    public function current_plugin(): ?string
    {
        $last = end( $this->plugin_stack );
        return $last !== false ? $last : null;
    }

    /**
     * Wrap an existing wpdb instance with a Proxy_WPDB.
     */
    public function proxy( \wpdb $original ): \wpdb
    {
        return new Proxy_WPDB( $original, $this );
    }

    /**
     * Intercept and validate a SQL query against the active plugin's manifest.
     *
     * Called by Proxy_WPDB before every query().
     *
     * @param string $sql  The raw SQL query string.
     *
     * @return string      The (possibly modified) SQL, or empty string to block.
     */
    public function intercept( string $sql ): string
    {
        $plugin_slug = $this->current_plugin();

        if ( $plugin_slug === null ) {
            return $sql;
        }

        $parsed = $this->lex_sql( $sql );
        if ( $parsed === null ) {
            return $sql;
        }

        $operation = $parsed['operation'];
        $tables    = $parsed['tables'];

        foreach ( $tables as $table ) {
            $capability = "db:{$operation}";

            $permitted = $this->manifest_validator->check(
                $plugin_slug,
                $capability,
                $table
            );

            if ( ! $permitted ) {
                if ( $this->profiler !== null ) {
                    $this->profiler->record_god_mode_action( $plugin_slug, [
                        'type'   => 'sql',
                        'sql'    => $sql,
                        'table'  => $table,
                        'action' => $operation,
                    ] );
                }

                if ( $this->config->is_enforce_mode() ) {
                    $this->logger->log( AuditLogger::SECURITY, 'SQL query blocked', [
                        'plugin'    => $plugin_slug,
                        'sql'       => $sql,
                        'table'     => $table,
                        'operation' => $operation,
                    ] );
                    return '';
                }

                $this->logger->log( AuditLogger::WARNING, 'SQL query not in manifest', [
                    'plugin'    => $plugin_slug,
                    'sql'       => $sql,
                    'table'     => $table,
                    'operation' => $operation,
                ] );
            }
        }

        return $sql;
    }

    /**
     * Lightweight SQL lexer — determines operation type and referenced tables.
     *
     * Supports SELECT, INSERT, UPDATE, DELETE, REPLACE, CREATE, ALTER, DROP, TRUNCATE.
     * Handles JOINs, subqueries (simplified), and multi-table statements.
     *
     * @return array{operation: string, tables: string[]}|null
     */
    public function lex_sql( string $sql ): ?array
    {
        $sql = trim( $sql );
        if ( $sql === '' ) {
            return null;
        }

        $upper = strtoupper( $sql );

        $operation = 'read';
        if ( str_starts_with( $upper, 'INSERT' ) ) {
            $operation = 'write';
        } elseif ( str_starts_with( $upper, 'UPDATE' ) ) {
            $operation = 'write';
        } elseif ( str_starts_with( $upper, 'DELETE' ) ) {
            $operation = 'delete';
        } elseif ( str_starts_with( $upper, 'REPLACE' ) ) {
            $operation = 'write';
        } elseif ( str_starts_with( $upper, 'CREATE' ) ) {
            $operation = 'alter';
        } elseif ( str_starts_with( $upper, 'ALTER' ) ) {
            $operation = 'alter';
        } elseif ( str_starts_with( $upper, 'DROP' ) ) {
            $operation = 'alter';
        } elseif ( str_starts_with( $upper, 'TRUNCATE' ) ) {
            $operation = 'alter';
        } elseif ( str_starts_with( $upper, 'SELECT' ) ) {
            $operation = 'read';
        }

        $tables = $this->extract_tables( $sql, $upper );

        return [
            'operation' => $operation,
            'tables'    => $tables,
        ];
    }

    /**
     * Extract table names from SQL using regex patterns.
     *
     * Handles: FROM, JOIN, INTO, UPDATE, TABLE (for DDL), and
     * handles backtick-quoted and unquoted identifiers.
     */
    private function extract_tables( string $sql, string $upper ): array
    {
        $tables = [];

        $patterns = [
            '/\bFROM\s+`?(\w+)`?/i',
            '/\bJOIN\s+`?(\w+)`?/i',
            '/\bINTO\s+`?(\w+)`?/i',
            '/\bUPDATE\s+`?(\w+)`?/i',
            '/\bTABLE\s+`?(\w+)`?/i',
            '/\bTABLE\s+`?(\w+)`?\s*\./i',
        ];

        foreach ( $patterns as $pattern ) {
            if ( preg_match_all( $pattern, $sql, $matches ) ) {
                foreach ( $matches[1] as $table ) {
                    $table = strtolower( $table );
                    if ( ! in_array( $table, $tables, true ) ) {
                        $tables[] = $table;
                    }
                }
            }
        }

        return $tables;
    }
}
