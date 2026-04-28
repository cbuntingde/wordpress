<?php
/**
 * Plugin Manifest Value Object
 *
 * Represents a parsed blueprint.json manifest for a single plugin.
 * Provides typed accessors for every capability dimension and a
 * policy-checking interface used by the ManifestValidator and
 * DatabaseProxy.
 *
 * @package Axiom\Security
 */

declare(strict_types=1);

namespace Axiom\Security;

final class PluginManifest
{
    private array $data;

    public const CAP_DB_READ       = 'db:read';
    public const CAP_DB_WRITE      = 'db:write';
    public const CAP_DB_DELETE     = 'db:delete';
    public const CAP_DB_ALTER      = 'db:alter';
    public const CAP_FILESYSTEM_READ  = 'filesystem:read';
    public const CAP_FILESYSTEM_WRITE = 'filesystem:write';
    public const CAP_NETWORK_OUTBOUND = 'network:outbound';
    public const CAP_WP_HOOKS_READ    = 'wp:hooks:read_only';
    public const CAP_WP_HOOKS_WRITE   = 'wp:hooks:write';
    public const CAP_WP_OPTIONS_READ  = 'wp:options:read';
    public const CAP_WP_OPTIONS_WRITE = 'wp:options:write';
    public const CAP_WP_USERS_READ    = 'wp:users:read';
    public const CAP_WP_USERS_WRITE   = 'wp:users:write';
    public const CAP_EXEC            = 'exec';

    public const ALL_CAPABILITIES = [
        self::CAP_DB_READ,
        self::CAP_DB_WRITE,
        self::CAP_DB_DELETE,
        self::CAP_DB_ALTER,
        self::CAP_FILESYSTEM_READ,
        self::CAP_FILESYSTEM_WRITE,
        self::CAP_NETWORK_OUTBOUND,
        self::CAP_WP_HOOKS_READ,
        self::CAP_WP_HOOKS_WRITE,
        self::CAP_WP_OPTIONS_READ,
        self::CAP_WP_OPTIONS_WRITE,
        self::CAP_WP_USERS_READ,
        self::CAP_WP_USERS_WRITE,
        self::CAP_EXEC,
    ];

    public function __construct( array $data )
    {
        $this->data = $data;
    }

    /**
     * Get the plugin identifier from the manifest.
     */
    public function id(): string
    {
        return $this->data['id'] ?? 'unknown';
    }

    /**
     * Get the human-readable plugin name.
     */
    public function name(): string
    {
        return $this->data['name'] ?? $this->id();
    }

    /**
     * Get the manifest schema version.
     */
    public function version(): string
    {
        return $this->data['manifest_version'] ?? '1.0';
    }

    /**
     * Get the raw permissions block.
     */
    public function permissions(): array
    {
        return $this->data['permissions'] ?? [];
    }

    /**
     * Get allowed database tables for a given operation type.
     *
     * Operation types: read, write, delete, alter
     */
    public function allowed_db_tables( string $operation = 'read' ): array
    {
        $db = $this->permissions()['db'] ?? [];
        return $db[ $operation ] ?? $db[ 'tables' ] ?? [];
    }

    /**
     * Check if a specific table:operation pair is permitted.
     */
    public function can_access_table( string $table, string $operation = 'read' ): bool
    {
        $allowed = $this->allowed_db_tables( $operation );
        foreach ( $allowed as $pattern ) {
            if ( fnmatch( $pattern, $table ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get allowed filesystem paths.
     */
    public function allowed_filesystem_paths(): array
    {
        return $this->permissions()['filesystem'] ?? [];
    }

    /**
     * Check if a given filesystem path is accessible for the specified operation.
     */
    public function can_access_filesystem( string $path, string $operation = 'read' ): bool
    {
        $paths = $this->allowed_filesystem_paths();
        foreach ( $paths as $allowed ) {
            $parts  = explode( ':', $allowed, 2 );
            $op     = $parts[0] ?? 'read';
            $pattern = $parts[1] ?? $parts[0] ?? '';
            if ( $op === $operation && fnmatch( $pattern, $path ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get allowed outbound network domains.
     */
    public function allowed_network_domains(): array
    {
        return $this->permissions()['network']['outbound'] ?? [];
    }

    /**
     * Check if outbound HTTP to a given domain is permitted.
     */
    public function can_network_outbound( string $domain ): bool
    {
        $allowed = $this->allowed_network_domains();
        foreach ( $allowed as $pattern ) {
            if ( fnmatch( $pattern, $domain ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get allowed WP hook subscriptions (read-only pattern list).
     */
    public function allowed_hooks_read(): array
    {
        return $this->permissions()['wp']['hooks']['read_only'] ?? [];
    }

    /**
     * Get allowed WP hooks for mutation (add_action / add_filter).
     */
    public function allowed_hooks_write(): array
    {
        return $this->permissions()['wp']['hooks']['write'] ?? [];
    }

    /**
     * Check if a given hook name may be subscribed to.
     */
    public function can_subscribe_hook( string $hook_name, bool $write = false ): bool
    {
        $list = $write ? $this->allowed_hooks_write() : $this->allowed_hooks_read();
        foreach ( $list as $pattern ) {
            if ( fnmatch( $pattern, $hook_name ) ) {
                return true;
            }
        }
        return $write ? false : true;
    }

    /**
     * Get allowed WP option keys for reading.
     */
    public function allowed_options_read(): array
    {
        return $this->permissions()['wp']['options']['read'] ?? [];
    }

    /**
     * Get allowed WP option keys for writing.
     */
    public function allowed_options_write(): array
    {
        return $this->permissions()['wp']['options']['write'] ?? [];
    }

    /**
     * Check if an option key may be read.
     */
    public function can_read_option( string $option ): bool
    {
        $allowed = $this->allowed_options_read();
        foreach ( $allowed as $pattern ) {
            if ( fnmatch( $pattern, $option ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if an option key may be written.
     */
    public function can_write_option( string $option ): bool
    {
        $allowed = $this->allowed_options_write();
        foreach ( $allowed as $pattern ) {
            if ( fnmatch( $pattern, $option ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get allowed user capabilities for read.
     */
    public function allowed_users_read(): array
    {
        return $this->permissions()['wp']['users']['read'] ?? [];
    }

    /**
     * Check if a user capability/category is readable.
     */
    public function can_read_user_data( string $capability ): bool
    {
        $allowed = $this->allowed_users_read();
        foreach ( $allowed as $pattern ) {
            if ( fnmatch( $pattern, $capability ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Is shell execution permitted?
     */
    public function can_exec(): bool
    {
        return in_array( self::CAP_EXEC, $this->data['permissions']['system'] ?? [], true );
    }

    /**
     * Get the resource limits block.
     */
    public function resource_limits(): array
    {
        return $this->data['resource_limits'] ?? [];
    }

    /**
     * Get custom CPU limit for this plugin (ms).
     */
    public function cpu_limit_ms(): int
    {
        return $this->resource_limits()['cpu_ms'] ?? 0;
    }

    /**
     * Get custom memory limit for this plugin (MB).
     */
    public function memory_limit_mb(): int
    {
        return $this->resource_limits()['memory_mb'] ?? 0;
    }

    /**
     * Get the isolation mode requested.
     */
    public function isolation_mode(): string
    {
        return $this->data['isolation'] ?? 'namespace';
    }

    /**
     * Serialize the manifest data for auditing/logging.
     */
    public function to_array(): array
    {
        return $this->data;
    }
}
