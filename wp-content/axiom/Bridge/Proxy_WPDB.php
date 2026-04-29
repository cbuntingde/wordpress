<?php
/**
 * Proxy_WPDB — Transparent Delegation with SQL Interception
 *
 * Extends wpdb to intercept every public query entry point.
 * Delegates all real database work to the original $wpdb instance
 * while routing every SQL string through the DatabaseProxy for
 * manifest-based capability validation.
 *
 * Supports the full wpdb public API:
 *   - query(), get_results(), get_row(), get_var(), get_col()
 *   - insert(), update(), replace(), delete()
 *   - prepare(), escape(), etc.
 *
 * @package Axiom\Bridge
 */

declare(strict_types=1);

namespace Axiom\Bridge;

/**
 * @property-read \wpdb $inner The original delegated wpdb instance.
 */
#[AllowDynamicProperties]
class Proxy_WPDB extends \wpdb
{
    private \wpdb $inner;
    private DatabaseProxy $proxy;

    /**
     * Delegate property access to the inner wpdb instance.
     */
    public function __get( $name )
    {
        return $this->inner->$name;
    }

    public function __set( $name, $value ): void
    {
        $this->inner->$name = $value;
    }

    public function __isset( $name ): bool
    {
        return isset( $this->inner->$name );
    }

    /**
     * @param \wpdb        $original The real wpdb instance to delegate to.
     * @param DatabaseProxy $proxy   The Axiom interception layer.
     */
    public function __construct( \wpdb $original, DatabaseProxy $proxy )
    {
        $this->inner = $original;
        $this->proxy = $proxy;
    }

    /**
     * Intercept the primary query method.
     */
    public function query( $query ): int|false
    {
        $intercepted = $this->proxy->intercept( $query );

        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }

        return $this->inner->query( $intercepted );
    }

    /**
     * Proxy: insert
     */
    public function insert( $table, $data, $format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "INSERT INTO {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->insert( $table, $data, $format );
    }

    /**
     * Proxy: update
     */
    public function update( $table, $data, $where, $format = null, $where_format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "UPDATE {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->update( $table, $data, $where, $format, $where_format );
    }

    /**
     * Proxy: replace
     */
    public function replace( $table, $data, $format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "REPLACE {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->replace( $table, $data, $format );
    }

    /**
     * Proxy: delete
     */
    public function delete( $table, $where, $where_format = null ): int|false
    {
        $intercepted = $this->proxy->intercept( "DELETE FROM {$table}" );
        if ( $intercepted === '' ) {
            $this->last_error = 'Blocked by Axiom security policy.';
            return false;
        }
        return $this->inner->delete( $table, $where, $where_format );
    }

    /**
     * Proxy: get_results
     */
    public function get_results( $query = null, $output = OBJECT ): array|object|null
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return null;
            }
            $query = $intercepted;
        }
        return $this->inner->get_results( $query, $output );
    }

    /**
     * Proxy: get_row
     */
    public function get_row( $query = null, $output = OBJECT, $y = 0 ): array|object|null
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return null;
            }
            $query = $intercepted;
        }
        return $this->inner->get_row( $query, $output, $y );
    }

    /**
     * Proxy: get_var
     */
    public function get_var( $query = null, $x = 0, $y = 0 ): string|null|int|float
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return null;
            }
            $query = $intercepted;
        }
        return $this->inner->get_var( $query, $x, $y );
    }

    /**
     * Proxy: get_col
     */
    public function get_col( $query = null, $x = 0 ): array
    {
        if ( $query !== null ) {
            $intercepted = $this->proxy->intercept( $query );
            if ( $intercepted === '' ) {
                $this->last_error = 'Blocked by Axiom security policy.';
                return [];
            }
            $query = $intercepted;
        }
        return $this->inner->get_col( $query, $x );
    }

    /**
     * Delegate prepare directly — no interception needed.
     */
    public function prepare( $query, ...$args ): string|int|float|bool|null
    {
        return $this->inner->prepare( $query, ...$args );
    }

    /**
     * Delegate esc_like directly.
     */
    public function esc_like( $text ): string
    {
        return $this->inner->esc_like( $text );
    }

    /**
     * Delegate flush directly.
     */
    public function flush( $flush = true ): void
    {
        $this->inner->flush( $flush );
    }

    /**
     * Delegate db_connect directly.
     */
    public function db_connect( $allow_bail = true ): void
    {
        $this->inner->db_connect( $allow_bail );
    }

    /**
     * Delegate init_charset directly.
     */
    public function init_charset(): bool
    {
        return $this->inner->init_charset();
    }

    /**
     * Delegate set_charset directly.
     */
    public function set_charset( $dbh = null, $charset = null, $collate = null ): void
    {
        $this->inner->set_charset( $dbh, $charset, $collate );
    }

    /**
     * Delegate select directly.
     */
    public function select( $db, $dbh = null ): void
    {
        $this->inner->select( $db, $dbh );
    }

    /**
     * Delegate print_error directly.
     */
    public function print_error( $str = '' ): void
    {
        $this->inner->print_error( $str );
    }

    /**
     * Delegate show_errors / hide_errors directly.
     */
    public function show_errors( $show = true ): bool
    {
        return $this->inner->show_errors( $show );
    }

    public function hide_errors(): bool
    {
        return $this->inner->hide_errors();
    }

    public function suppress_errors( $suppress = true ): bool
    {
        return $this->inner->suppress_errors( $suppress );
    }

    /**
     * Delegate get_caller directly.
     */
    public function get_caller(): string
    {
        return $this->inner->get_caller();
    }

    /**
     * Delegate check_database_version directly.
     */
    public function check_database_version(): void
    {
        $this->inner->check_database_version();
    }

    /**
     * Delegate supports_collation directly.
     */
    public function supports_collation(): bool
    {
        return $this->inner->supports_collation();
    }

    /**
     * Delegate has_cap directly.
     */
    public function has_cap( $db_cap ): bool
    {
        return $this->inner->has_cap( $db_cap );
    }

    /**
     * Delegate db_version directly.
     */
    public function db_version( $dbh_or_table = false ): string|null
    {
        return $this->inner->db_version( $dbh_or_table );
    }

    /**
     * Delegate table_exists directly.
     */
    public function table_exists( $table ): bool
    {
        return $this->inner->table_exists( $table );
    }

    /**
     * Delegate get_table_from_query directly.
     */
    public function get_table_from_query( $query ): string|false
    {
        return $this->inner->get_table_from_query( $query );
    }

    /**
     * Delegate processes() directly.
     */
    public function processes(): array|false
    {
        return $this->inner->processes();
    }

    /**
     * Delegate close() directly.
     */
    public function close(): void
    {
        $this->inner->close();
    }

    /**
     * Delegate __wakeup directly.
     */
    public function __wakeup(): void
    {
        $this->inner->__wakeup();
    }

    public function __sleep(): array
    {
        return array_merge( $this->inner->__sleep(), [ 'inner', 'proxy' ] );
    }

    /**
     * Delegate bail_handler directly.
     */
    public function bail_handler( $message ): void
    {
        $this->inner->bail_handler( $message );
    }

    /**
     * Delegate check_connection directly.
     */
    public function check_connection( $allow_bail = true ): void
    {
        $this->inner->check_connection( $allow_bail );
    }

    /**
     * Delegate load_col_info directly.
     */
    public function load_col_info(): void
    {
        $this->inner->load_col_info();
    }

    /**
     * Delegate get_col_info directly.
     */
    public function get_col_info( $info_type = 'name', $col_offset = -1 ): array|object|null
    {
        return $this->inner->get_col_info( $info_type, $col_offset );
    }

    /**
     * Delegate __call for any dynamic methods on the inner wpdb.
     */
    public function __call( string $name, array $arguments ): mixed
    {
        return $this->inner->$name( ...$arguments );
    }
}
