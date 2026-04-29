<?php
/**
 * Kernel Configuration
 *
 * Reads from wp-config.php constants and axiom-config.php to
 * configure the Axiom sandboxing kernel at bootstrap time.
 *
 * @package Axiom\Kernel
 */

declare(strict_types=1);

namespace Axiom\Kernel;

final class KernelConfig
{
    public const MODE_ENFORCE  = 'enforce';
    public const MODE_AUDIT    = 'audit';
    public const MODE_LEARNING = 'learning';
    public const MODE_DISABLED = 'disabled';

    private string $mode;
    private bool $learning_mode;
    private int $cpu_limit_ms;
    private int $memory_limit_mb;
    private bool $strict_sql;
    private array $trusted_plugins;
    private string $manifest_dir;
    private string $log_level;
    private int $performance_budget_ms;
    private bool $enable_wasm;

    private function __construct( array $options )
    {
        $this->mode               = $options['mode'] ?? self::MODE_AUDIT;
        $this->learning_mode      = $options['learning_mode'] ?? true;
        $this->cpu_limit_ms       = $options['cpu_limit_ms'] ?? 500;
        $this->memory_limit_mb    = $options['memory_limit_mb'] ?? 64;
        $this->strict_sql         = $options['strict_sql'] ?? false;
        $this->trusted_plugins    = $options['trusted_plugins'] ?? [];
        $this->manifest_dir       = $options['manifest_dir'] ?? WP_CONTENT_DIR . '/axiom/manifests';
        $this->log_level          = $options['log_level'] ?? 'warning';
        $this->performance_budget_ms = $options['performance_budget_ms'] ?? 50;
        $this->enable_wasm        = $options['enable_wasm'] ?? false;
    }

    /**
     * Load configuration from PHP constants, axiom-config.php,
     * axiom_settings DB option, and environment.
     */
    public static function load(): self
    {
        $config_file = WP_CONTENT_DIR . '/axiom-config.php';
        $options     = [];

        if ( file_exists( $config_file ) ) {
            $options = (array) include $config_file;
        }

        // DB settings (admin UI) fill in gaps the config file didn't set.
        // Only merge when the option system is fully bootstrapped (wp_cache_available).
        if ( function_exists( 'get_option' ) && function_exists( 'wp_cache_get' ) ) {
            $db_settings = \get_option( 'axiom_settings', [] );
            if ( is_array( $db_settings ) && $db_settings !== [] ) {
                $options = array_merge( $options, $db_settings );
            }
        }

        $options['mode']            = defined( 'AXIOM_MODE' )
            ? AXIOM_MODE
            : ( $options['mode'] ?? self::MODE_AUDIT );
        $options['learning_mode']   = defined( 'AXIOM_LEARNING_MODE' )
            ? (bool) AXIOM_LEARNING_MODE
            : ( $options['learning_mode'] ?? true );
        $options['cpu_limit_ms']    = defined( 'AXIOM_CPU_LIMIT_MS' )
            ? (int) AXIOM_CPU_LIMIT_MS
            : ( $options['cpu_limit_ms'] ?? 500 );
        $options['memory_limit_mb'] = defined( 'AXIOM_MEMORY_LIMIT_MB' )
            ? (int) AXIOM_MEMORY_LIMIT_MB
            : ( $options['memory_limit_mb'] ?? 64 );
        $options['strict_sql']      = defined( 'AXIOM_STRICT_SQL' )
            ? (bool) AXIOM_STRICT_SQL
            : ( $options['strict_sql'] ?? false );
        $options['enable_wasm']     = defined( 'AXIOM_ENABLE_WASM' )
            ? (bool) AXIOM_ENABLE_WASM
            : ( $options['enable_wasm'] ?? false );
        $options['log_level']       = defined( 'AXIOM_LOG_LEVEL' )
            ? AXIOM_LOG_LEVEL
            : ( $options['log_level'] ?? 'warning' );

        if ( defined( 'AXIOM_MANIFEST_DIR' ) ) {
            $options['manifest_dir'] = AXIOM_MANIFEST_DIR;
        }

        if ( defined( 'AXIOM_TRUSTED_PLUGINS' ) ) {
            $options['trusted_plugins'] = explode( ',', AXIOM_TRUSTED_PLUGINS );
        }

        return new self( $options );
    }

    public function mode(): string               { return $this->mode; }
    public function is_learning_mode(): bool      { return $this->learning_mode; }
    public function is_enforce_mode(): bool       { return $this->mode === self::MODE_ENFORCE; }
    public function is_audit_mode(): bool         { return $this->mode === self::MODE_AUDIT; }
    public function is_disabled(): bool           { return $this->mode === self::MODE_DISABLED; }
    public function cpu_limit_ms(): int           { return $this->cpu_limit_ms; }
    public function memory_limit_mb(): int        { return $this->memory_limit_mb; }
    public function strict_sql(): bool            { return $this->strict_sql; }
    public function manifest_dir(): string        { return $this->manifest_dir; }
    public function log_level(): string           { return $this->log_level; }
    public function performance_budget_ms(): int  { return $this->performance_budget_ms; }
    public function enable_wasm(): bool           { return $this->enable_wasm; }

    public function is_plugin_trusted( string $plugin_slug ): bool
    {
        return in_array( $plugin_slug, $this->trusted_plugins, true );
    }

    public function performance_tax_budget(): float
    {
        return 0.15;
    }
}
